import json

import click
from tabulate import tabulate

from alertaclient.models.heartbeat import Heartbeat
from alertaclient.utils import origin

from datetime import datetime

@click.command('heartbeats', short_help='List heartbeats')
@click.option('--alert', is_flag=True, help='Alert on stale or slow heartbeats')
@click.option('--severity', '-s', metavar='SEVERITY', default='major', help='Severity for heartbeat alerts')
@click.option('--timeout', metavar='SECONDS', type=int, help='Seconds before stale heartbeat alerts will be expired')
@click.option('--purge', is_flag=True, help='Delete all stale heartbeats')
@click.pass_obj
def cli(obj, alert, severity, timeout, purge):
    """List heartbeats."""
    start = datetime.now()
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
        with click.progressbar(heartbeats, label=f'Alerting {len(heartbeats)} heartbeats') as bar:
            alerts = client.get_alerts(query=[('environment', 'Heartbeats')], page_size=len(heartbeats))
            new_alerts = []

            for b in bar:
                want_environment = b.attributes.pop('environment', 'Heartbeats')
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
                alert_exists = False
                for alert in alerts:
                    if alert.environment == want_environment and alert.resource == b.origin:
                        alert_exists = True
                        if state['event'] != alert.event:
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
                        break
                if not alert_exists:
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

            if len(new_alerts) > 0:
                client.send_alerts(new_alerts)
            end = datetime.now()
            print('\n')
            print(end - start)
