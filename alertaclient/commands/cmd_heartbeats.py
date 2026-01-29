import json

import click
from tabulate import tabulate

from alertaclient.models.heartbeat import Heartbeat
from alertaclient.utils import origin


@click.command('heartbeats', short_help='List heartbeats')
@click.option('--alert', is_flag=True, help='Alert on stale or slow heartbeats')
@click.option('--severity', '-s', metavar='SEVERITY', default='major', help='Severity for heartbeat alerts')
@click.option('--timeout', metavar='SECONDS', type=int, help='Seconds before stale heartbeat alerts will be expired')
@click.option('--purge', is_flag=True, help='Delete all stale heartbeats')
@click.pass_obj
def cli(obj, alert, severity, timeout, purge):
    """List heartbeats."""
    client = obj['client']

    try:
        default_normal_severity = obj['alarm_model']['defaults']['normal_severity']
    except KeyError:
        default_normal_severity = 'normal'

    if severity in ['normal', 'ok', 'cleared']:
        raise click.UsageError('Must be a non-normal severity. "{}" is one of {}'.format(
            severity, ', '.join(['normal', 'ok', 'cleared']))
        )

    if severity not in obj['alarm_model']['severity'].keys():
        raise click.UsageError('Must be a valid severity. "{}" is not one of {}'.format(
            severity, ', '.join(obj['alarm_model']['severity'].keys()))
        )

    if obj['output'] == 'json':
        r = client.http.get('/heartbeats?page-size=ALL')
        heartbeats = [Heartbeat.parse(hb) for hb in r['heartbeats']]
        click.echo(json.dumps(r['heartbeats'], sort_keys=True, indent=4, ensure_ascii=False))
    else:
        timezone = obj['timezone']
        headers = {
            'id': 'ID', 'origin': 'ORIGIN', 'customer': 'CUSTOMER', 'tags': 'TAGS', 'attributes': 'ATTRIBUTES',
            'createTime': 'CREATED', 'receiveTime': 'RECEIVED', 'since': 'SINCE', 'timeout': 'TIMEOUT',
            'latency': 'LATENCY', 'maxLatency': 'MAX LATENCY', 'status': 'STATUS'
        }
        heartbeats = client.get_heartbeats()
        click.echo(tabulate([h.tabular(timezone) for h in heartbeats], headers=headers, tablefmt=obj['output']))

    not_ok = [hb for hb in heartbeats if hb.status != 'ok']
    if purge:
        with click.progressbar(not_ok, label=f'Purging {len(not_ok)} heartbeats') as bar:
            for b in bar:
                client.delete_heartbeat(b.id)

    if alert:
        with click.progressbar(heartbeats, label=f'Checking {len(heartbeats)} heartbeats') as bar:
            alerts = client.get_alerts(query=[('event', '~Heartbeat')], page_size='ALL')
            new_alerts = []

            for b in bar:
                want_environment = 'Heartbeats'
                want_severity = b.attributes.pop('severity', severity)
                want_service = b.attributes.pop('service', ['Alerta'])
                want_group = b.attributes.pop('group', 'System')
                state_map = {
                    'expired': {
                        'event': 'HeartbeatFail',
                        'value': f'{b.since}',
                        'text': f'Heartbeat not received in {b.timeout} seconds',
                        'severity': want_severity
                    },
                    'slow': {
                        'event': 'HeartbeatSlow',
                        'value': f'{b.latency}ms',
                        'text': f'Heartbeat took more than {b.max_latency}ms to be processed',
                        'severity': want_severity
                    },
                    'ok': {
                        'event': 'HeartbeatOK',
                        'value': '',
                        'text': 'Heartbeat OK',
                        'severity': default_normal_severity
                    }
                }

                state = state_map[b.status]
                found_alert = None
                for a in alerts:
                    if a.environment == want_environment and a.resource == b.origin:
                        found_alert = alerts.pop(alerts.index(a))
                        break

                if found_alert is None or state['event'] != found_alert.event:
                    new_alerts.append(
                        {
                            'resource': b.origin,
                            'event': state['event'],
                            'environment': want_environment,
                            'severity': state['severity'],
                            'correlate': ['HeartbeatFail', 'HeartbeatSlow', 'HeartbeatOK'],
                            'service': want_service,
                            'group': want_group,
                            'value': state['value'],
                            'text': state['text'],
                            'tags': b.tags,
                            'attributes': b.attributes,
                            'origin': origin(),
                            'type': 'heartbeatAlert',
                            'timeout': timeout,
                            'customer': b.customer
                        }
                    )

        number_of_co = 50
        number_of_alerts = len(new_alerts)
        number_of_sends = number_of_alerts // number_of_co
        alert_groups = [new_alerts[i * number_of_co:(i + 1) * number_of_co] for i in range(number_of_sends)]
        if number_of_alerts % number_of_co:
            alert_groups.append(new_alerts[number_of_co * number_of_sends:number_of_co * number_of_sends + number_of_alerts % number_of_co])

        with click.progressbar(alert_groups, label=f'Alerting {len(new_alerts)} heartbeats') as bar:
            for b in bar:
                client.send_alerts(b)

        
        alerts = [alert.id for alert in alerts]            
        number_of_deletes = len(alerts)
        number_of_delete_sends = number_of_deletes // number_of_co
        delete_groups = [alerts[i * number_of_co:(i + 1) * number_of_co] for i in range(number_of_delete_sends)]
        if number_of_deletes % number_of_co:
            delete_groups.append(alerts[number_of_co * number_of_delete_sends:number_of_co * number_of_delete_sends + number_of_deletes % number_of_co])
        with click.progressbar(delete_groups, label=f'Removing {len(alerts)} old alerts') as bar:
            for delete_group in bar:
                client.delete_alerts(delete_group)
