#!/usr/bin/env python
"""
    Alerta unified command-line tool
"""

import os
import sys
import argparse
import time
import json
import requests
import logging
import codecs

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from datetime import datetime, timedelta

from alerta.api import ApiClient
from alerta.alert import Alert, AlertDocument
from alerta.heartbeat import Heartbeat
from alerta.top import Screen

import pkg_resources  # part of setuptools
__version__ = pkg_resources.require("alerta")[0].version

prog = os.path.basename(sys.argv[0])

LOG = logging.getLogger(__name__)
root = logging.getLogger()

OPTIONS = {
    'config_file': '~/.alerta.conf',
    'profile':     None,
    'endpoint':    'http://localhost:8080',
    'key':         '',
    'timezone':    'Europe/London',
    'output':      'text',
    'color':       True,
    'debug':       False,
    'severity':    "normal",
    'timeout':     86400
}

DEFAULT_SEVERITY = "normal"  # "normal", "ok" or "clear"
DEFAULT_TIMEOUT = 86400

_COLOR_MAP = {
    "critical": '\033[91m',
    "major": '\033[95m',
    "minor": '\033[93m',
    "warning": '\033[96m',
    "indeterminate": '\033[92m',
    "cleared": '\033[92m',
    "normal": '\033[92m',
    "informational": '\033[92m',
    "ok": '\033[92m',
    "debug": '\033[90m',
    "auth": '\033[90m',
    "unknown": '\033[90m',
}
_ENDC = '\033[0m'


class AlertCommand(object):

    def __init__(self):

        self.api = ApiClient()

    def set(self, endpoint, key):

        self.api = ApiClient(endpoint=endpoint, key=key)

    def send(self, args):

        try:
            alert = Alert(
                resource=args.resource,
                event=args.event,
                environment=args.environment,
                severity=args.severity,
                correlate=args.correlate,
                status=args.status,
                service=args.service,
                group=args.group,
                value=args.value,
                text=args.text,
                tags=args.tags,
                attributes=dict([attrib.split('=') for attrib in args.attributes]),
                origin=args.origin,
                event_type=args.event_type,
                timeout=args.timeout,
                raw_data=args.raw_data
            )
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        try:
            response = self.api.send(alert)
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        if response['status'] == 'ok':
            if not 'alert' in response:
                print(response['id'])
                sys.exit(0)
            if response['alert']['repeat']:
                info = "%s duplicates" % response['alert']['duplicateCount']
            else:
                info = "%s -> %s" % (response['alert']['previousSeverity'], response['alert']['severity'])
            print("{} ({})".format(response['id'], info))
        else:
            LOG.error(response['message'])
            sys.exit(1)

    def heartbeat(self, args):

        try:
            heartbeat = Heartbeat(
                origin=args.origin,
                tags=args.tags,
                timeout=args.timeout
            )
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        try:
            response = self.api.send(heartbeat)
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        if response['status'] == 'ok':
            print(response['id'])
        else:
            LOG.error(response['message'])
            sys.exit(1)

    def query(self, args, from_date=None):

        response = self._alerts(args.filters, from_date)
        alerts = response['alerts']

        if args.output == "json":
            print(json.dumps(alerts, indent=4))
            sys.exit(0)

        for alert in reversed(alerts):

            a = AlertDocument.parse_alert(alert)

            line_color = ''
            end_color = _ENDC

            if args.color:
                line_color = _COLOR_MAP.get(a.severity, _COLOR_MAP['unknown'])

            print(line_color + '{0}|{1}|{2}|{3:5d}|{4:<5s}|{5:<10s}|{6:<18s}|{7:12s}|{8:16s}|{9:12s}'.format(
                a.id[0:8],
                a.get_date('last_receive_time', 'local', args.timezone),
                a.severity,
                a.duplicate_count,
                a.environment,
                ','.join(a.service),
                a.resource,
                a.group,
                a.event,
                a.value) + end_color)
            print(line_color + '   |{}'.format(a.text) + end_color)

            if args.details:
                print(line_color + '    severity   | {} -> {}'.format(a.previous_severity, a.severity) + end_color)
                print(line_color + '    trend      | {}'.format(a.trend_indication) + end_color)
                print(line_color + '    status     | {}'.format(a.status) + end_color)
                print(line_color + '    resource   | {}'.format(a.resource) + end_color)
                print(line_color + '    group      | {}'.format(a.group) + end_color)
                print(line_color + '    event      | {}'.format(a.event) + end_color)
                print(line_color + '    value      | {}'.format(a.value) + end_color)
                print(line_color + '    tags       | {}'.format(' '.join(a.tags)) + end_color)

                for key, value in a.attributes.items():
                    print(line_color + '    {} | {}'.format(key.ljust(10), value) + end_color)

                latency = a.receive_time - a.create_time

                print(line_color + '        time created  | {}'.format(a.get_date('create_time', 'iso', args.timezone)) + end_color)
                print(line_color + '        time received | {}'.format(a.get_date('receive_time', 'iso', args.timezone)) + end_color)
                print(line_color + '        last received | {}'.format(a.get_date('last_receive_time', 'iso', args.timezone)) + end_color)
                print(line_color + '        latency       | {}ms'.format((latency.microseconds / 1000)) + end_color)
                print(line_color + '        timeout       | {}s'.format(a.timeout) + end_color)

                print(line_color + '            alert id     | {}'.format(a.id) + end_color)
                print(line_color + '            last recv id | {}'.format(a.last_receive_id) + end_color)
                print(line_color + '            environment  | {}'.format(a.environment) + end_color)
                print(line_color + '            service      | {}'.format(','.join(a.service)) + end_color)
                print(line_color + '            resource     | {}'.format(a.resource) + end_color)
                print(line_color + '            type         | {}'.format(a.event_type) + end_color)
                print(line_color + '            repeat       | {}'.format(a.repeat) + end_color)
                print(line_color + '            origin       | {}'.format(a.origin) + end_color)
                print(line_color + '            correlate    | {}'.format(','.join(a.correlate)) + end_color)

        return response.get('lastTime', '')

    def watch(self, args):

        from_date = None
        while True:
            from_date = self.query(args, from_date)
            try:
                time.sleep(2)
            except (KeyboardInterrupt, SystemExit):
                sys.exit(0)

    def top(self, args):

        screen = Screen(endpoint=args.endpoint, key=args.key)

        try:
            screen.run()
        except RuntimeError as e:
            screen._reset()
            print(e)
            sys.exit(1)
        except (KeyboardInterrupt, SystemExit):
            screen.w.running = False
            screen._reset()
            print('Exiting...')
            sys.exit(0)

    def raw(self, args):

        response = self._alerts(args.filters)
        alerts = response['alerts']

        if args.output == "json":
            print(json.dumps(alerts, indent=4))
            sys.exit(0)

        for alert in reversed(alerts):
            line_color = ''
            end_color = _ENDC

            print(line_color + '%s' % alert['rawData'] + end_color)

    def history(self, args):

        response = self._history(args.filters)
        history = response['history']

        if args.output == "json":
            print(json.dumps(history, indent=4))
            sys.exit(0)

        for hist in history:

            line_color = ''
            end_color = _ENDC

            update_time = datetime.strptime(hist.get('updateTime', None), '%Y-%m-%dT%H:%M:%S.%fZ')

            if 'severity' in hist:
                if args.color:
                    line_color = _COLOR_MAP.get(hist['severity'], _COLOR_MAP['unknown'])
                print(line_color + '%s|%s|%s|%-5s|%-10s|%-18s|%s|%s|%s|%s' % (
                    hist['id'][0:8],
                    update_time.strftime('%Y/%m/%d %H:%M:%S'),
                    hist['severity'],
                    hist['environment'],
                    ','.join(hist['service']),
                    hist['resource'],
                    hist['group'],
                    hist['event'],
                    hist['value'],
                    hist['text']
                ) + end_color)

            if 'status' in hist:
                print(line_color + '%s|%s|%s|%-5s|%-10s|%-18s|%s|%s|%s|%s' % (
                    hist['id'][0:8],
                    update_time.strftime('%Y/%m/%d %H:%M:%S'),
                    hist['status'],
                    hist['environment'],
                    ','.join(hist['service']),
                    hist['resource'],
                    hist['group'],
                    hist['event'],
                    'n/a',
                    hist['text']
                ) + end_color)

    def tag(self, args):

        sys.stdout.write("Counting alerts: ")
        response = self._alerts(args.filters)
        alerts = response['alerts']
        total = response['total']
        sys.stdout.write("%s, done.\n" % total)

        sys.stdout.write("Tagging alerts: ")
        for i, alert in enumerate(alerts):
            pct = int(100.0 * i / total)
            sys.stdout.write("%3d%% (%d/%d)" % (pct, i, total))
            sys.stdout.flush()
            sys.stdout.write("\b" * (8 + len(str(i)) + len(str(total))))
            try:
                self.api.tag_alert(alert['id'], args.tags)
            except Exception as e:
                print()
                LOG.error(e)
                sys.exit(1)

        sys.stdout.write("100%% (%d/%d), done.\n" % (total, total))

    def untag(self, args):

        sys.stdout.write("Counting alerts: ")
        response = self._alerts(args.filters)
        alerts = response['alerts']
        total = response['total']
        sys.stdout.write("%s, done.\n" % total)

        sys.stdout.write("Un-tagging alerts: ")
        for i, alert in enumerate(alerts):
            pct = int(100.0 * i / total)
            sys.stdout.write("%3d%% (%d/%d)" % (pct, i, total))
            sys.stdout.flush()
            sys.stdout.write("\b" * (8 + len(str(i)) + len(str(total))))
            try:
                self.api.untag_alert(alert['id'], args.tags)
            except Exception as e:
                print()
                LOG.error(e)
                sys.exit(1)

        sys.stdout.write("100%% (%d/%d), done.\n" % (total, total))

    def ack(self, args):

        sys.stdout.write("Counting alerts: ")
        response = self._counts(args.filters)
        total = response['total']
        sys.stdout.write("%s, done.\n" % total)

        sys.stdout.write("Acking alerts: ")
        response = self._alerts(args.filters)
        alerts = response['alerts']
        for i, alert in enumerate(alerts):
            pct = int(100.0 * i / total)
            sys.stdout.write("%3d%% (%d/%d)" % (pct, i, total))
            sys.stdout.flush()
            sys.stdout.write("\b" * (8 + len(str(i)) + len(str(total))))
            try:
                self.api.ack_alert(alert['id'])
            except Exception as e:
                print()
                LOG.error(e)
                sys.exit(1)

        sys.stdout.write("100%% (%d/%d), done.\n" % (total, total))

    def unack(self, args):

        sys.stdout.write("Counting alerts: ")
        response = self._counts(args.filters)
        total = response['total']
        sys.stdout.write("%s, done.\n" % total)

        sys.stdout.write("un-Acking alerts: ")
        response = self._alerts(args.filters)
        alerts = response['alerts']
        for i, alert in enumerate(alerts):
            pct = int(100.0 * i / total)
            sys.stdout.write("%3d%% (%d/%d)" % (pct, i, total))
            sys.stdout.flush()
            sys.stdout.write("\b" * (8 + len(str(i)) + len(str(total))))
            try:
                self.api.unack_alert(alert['id'])
            except Exception as e:
                print()
                LOG.error(e)
                sys.exit(1)

        sys.stdout.write("100%% (%d/%d), done.\n" % (total, total))

    def close(self, args):

        sys.stdout.write("Counting alerts: ")
        response = self._counts(args.filters)
        total = response['total']
        sys.stdout.write("%s, done.\n" % total)

        sys.stdout.write("Closing alerts: ")
        response = self._alerts(args.filters)
        alerts = response['alerts']
        for i, alert in enumerate(alerts):
            pct = int(100.0 * i / total)
            sys.stdout.write("%3d%% (%d/%d)" % (pct, i, total))
            sys.stdout.flush()
            sys.stdout.write("\b" * (8 + len(str(i)) + len(str(total))))
            try:
                self.api.close_alert(alert['id'])
            except Exception as e:
                print()
                LOG.error(e)
                sys.exit(1)

        sys.stdout.write("100%% (%d/%d), done.\n" % (total, total))

    def delete(self, args):

        sys.stdout.write("Counting alerts: ")
        response = self._counts(args.filters)
        total = response['total']
        sys.stdout.write("%s, done.\n" % total)

        sys.stdout.write("Deleting alerts: ")
        response = self._alerts(args.filters)
        alerts = response['alerts']
        for i, alert in enumerate(alerts):
            pct = int(100.0 * i / total)
            sys.stdout.write("%3d%% (%d/%d)" % (pct, i, total))
            sys.stdout.flush()
            sys.stdout.write("\b" * (8 + len(str(i)) + len(str(total))))
            try:
                self.api.delete_alert(alert['id'])
            except Exception as e:
                print()
                LOG.error(e)
                sys.exit(1)

        sys.stdout.write("100%% (%d/%d), done.\n" % (total, total))

    def status(self, args):

        response = self._status()
        metrics = response['metrics']

        for metric in [m for m in metrics if m['type'] in ['gauge', 'counter', 'timer']]:
            if metric['type'] == 'gauge':
                print('{0:-28s} {1:-8s} {2:-26s} {3:-10s}'.format(metric['title'], metric['type'], metric['group'] + '.' + metric['name'], metric['value']))
            else:
                value = metric.get('count', 0)
                avg = int(metric['totalTime']) * 1.0 / int(metric['count'])
                print('{0:-28s} {1:-8s} {2:-26s} {3:-10s} {4:-3.2f} ms'.format(metric['title'], metric['type'], metric['group'] + '.' + metric['name'], value, avg))

        for metric in [m for m in metrics if m['type'] == 'text']:
            print('{0:-28s} {1:-8s} {2:-26s} {3:-10s}'.format(metric['title'], metric['type'], metric['group'] + '.' + metric['name'], metric['value']))

    @staticmethod
    def _build(filters, from_date=None, to_date=None):

        if filters:
            query = [tuple(x.split('=', 1)) for x in filters if '=' in x]
        else:
            query = list()

        if from_date:
            query.append(('from-date', from_date))

        if to_date:
            query.append(('to-date', to_date))

        if 'sort-by' not in query:
            query.append(('sort-by', 'lastReceiveTime'))

        return query

    def _alerts(self, filters, from_date=None, to_date=None):

        query = self._build(filters, from_date, to_date)

        try:
            response = self.api.get_alerts(query)
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        if response['status'] == "error":
            LOG.error(response['message'])
            sys.exit(1)

        return response

    def _counts(self, filters, from_date=None, to_date=None):

        query = self._build(filters, from_date, to_date)

        try:
            response = self.api.get_counts(query)
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        if response['status'] == "error":
            LOG.error(response['message'])
            sys.exit(1)

        return response

    def _history(self, filters, from_date=None, to_date=None):

        query = self._build(filters, from_date, to_date)

        try:
            response = self.api.get_history(query)
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        if response['status'] == "error":
            LOG.error(response['message'])
            sys.exit(1)

        return response

    def _status(self):

        try:
            response = self.api.get_status()
        except Exception as e:
            LOG.error(e)
            sys.exit(1)

        return response

    def help(self, args):

        pass

    def uptime(self, args):

        response = self._status()

        now = datetime.fromtimestamp(int(response['time']) / 1000.0)
        d = datetime(1, 1, 1) + timedelta(seconds=int(response['uptime']) / 1000.0)

        print('{0} up {1} days {2:02d}:{3:02d}'.format(
            now.strftime('%H:%M'),
            d.day - 1, d.hour, d.minute
        ))

    def version(self, args):

        response = self._status()

        print('{0} {1}'.format(
            response['application'],
            response['version'],
        ))
        print('alerta client {0}'.format(__version__))
        print('requests {0}'.format(requests.__version__))


class AlertaShell(object):

    def run(self):

        root.setLevel(logging.ERROR)
        LOG.setLevel(logging.ERROR)

        config_file = os.environ.get('ALERTA_CONF_FILE') or OPTIONS['config_file']

        config = configparser.RawConfigParser(defaults=OPTIONS)
        try:
            config.read(os.path.expanduser(config_file))
        except Exception:
            LOG.warning("Problem reading configuration file %s - is this an ini file?", config_file)
            sys.exit(1)

        profile_parser = argparse.ArgumentParser(
            add_help=False
        )
        profile_parser.add_argument(
            '--profile',
            help='Profile to apply from %s' % config_file
        )
        args, left = profile_parser.parse_known_args()

        want_profile = args.profile or os.environ.get('ALERTA_DEFAULT_PROFILE') or config.defaults().get('profile')

        if want_profile and config.has_section('profile %s' % want_profile):
            for opt in OPTIONS:
                OPTIONS[opt] = config.get('profile %s' % want_profile, opt)
        else:
            for opt in OPTIONS:
                OPTIONS[opt] = config.get('DEFAULT', opt)

        OPTIONS['endpoint'] = os.environ.get('ALERTA_ENDPOINT') or OPTIONS['endpoint']
        OPTIONS['key'] = os.environ.get('ALERTA_API_KEY') or OPTIONS['key']
        OPTIONS['color'] = os.environ.get('CLICOLOR') or OPTIONS['color']
        OPTIONS['debug'] = os.environ.get('DEBUG') or OPTIONS['debug']

        parser = argparse.ArgumentParser(
            prog='alerta',
            usage='alerta [OPTIONS] COMMAND [FILTERS]',
            description="Alerta client unified command-line tool",
            epilog='Filters:\n'
                   '    Query parameters can be used to filter alerts by any valid alert attribute\n\n'
                   '    resource=web01     Show alerts with resource equal to "web01"\n'
                   '    resource!=web01    Show all alerts except those with resource of "web01"\n'
                   '    event=~down        Show alerts that include "down" in event name\n'
                   '    event!=~down       Show all alerts that don\'t have "down" in event name\n\n'
                   '    Special query parameters include "limit", "sort-by", "from-date" and "q" (a\n'
                   '    json-compliant mongo query).\n',
            formatter_class=argparse.RawTextHelpFormatter,
            parents=[profile_parser]
        )
        parser.add_argument(
            '--endpoint-url',
            dest='endpoint',
            metavar='URL',
            help='API endpoint URL'
        )
        parser.add_argument(
            '--output',
            help='Output format of "text" or "json"'
        )
        parser.add_argument(
            '--json',
            '-j',
            action='store_true',
            help='Output in JSON format. Shortcut for "--output json"'
        )
        parser.add_argument(
            '--color',
            '--colour',
            action='store_true',
            help='Color-coded output based on severity'
        )
        parser.add_argument(
            '--no-color',
            '--no-colour',
            action='store_false',
            dest='color',
            help=argparse.SUPPRESS
        )
        parser.add_argument(
            '--debug',
            action='store_true',
            help='Print debug output'
        )
        parser.set_defaults(**OPTIONS)

        cli = AlertCommand()

        subparsers = parser.add_subparsers(
            title='Commands',
            metavar='COMMAND'
        )

        parser_send = subparsers.add_parser(
            'send',
            help='Send alert to server',
            usage='alerta [OPTIONS] send [-r RESOURCE] [-e EVENT] [-E ENVIRONMENT]\n'
                '                        [-s SEVERITY] [-C CORRELATE] [--status STATUS]\n'
                '                        [-S SERVICE] [-g GROUP] [-v VALUE] [-t TEXT]\n'
                '                        [-T TAG] [-A ATTRIBUTES] [-O ORIGIN]\n'
                '                        [--type EVENT_TYPE] [--timeout TIMEOUT]\n'
                '                        [--raw-data RAW_DATA]\n'
        )
        parser_send.add_argument(
            '-r',
            '--resource',
            help='resource under alarm'
        )
        parser_send.add_argument(
            '-e',
            '--event',
            help='event'
        )
        parser_send.add_argument(
            '-E',
            '--environment',
            help='environment eg. "production", "development", "testing"'
        )
        parser_send.add_argument(
            '-s',
            '--severity',
            help='severity'
        )
        parser_send.add_argument(
            '-C',
            '--correlate',
            action='append',
            help='correlate'
        )
        parser_send.add_argument(
            '--status',
            help='status should not normally be defined as it is server-assigned eg. "open", "closed"'
        )
        parser_send.add_argument(
            '-S',
            '--service',
            action='append',
            help='service affected eg. the application name, "Web", "Network", "Storage", "Database", "Security"'
        )
        parser_send.add_argument(
            '-g',
            '--group',
            help='group'
        )
        parser_send.add_argument(
            '-v',
            '--value',
            help='value'
        )
        parser_send.add_argument(
            '-t',
            '--text',
            help='Freeform alert text eg. "Host not responding to ping."'
        )
        parser_send.add_argument(
            '-T',
            '--tag',
            metavar='TAG',
            action='append',
            dest='tags',
            default=list(),
            help='List of tags eg. "London", "os:linux", "AWS/EC2".'
        )
        parser_send.add_argument(
            '-A',
            '--attribute',
            action='append',
            dest='attributes',
            default=list(),
            help='List of Key=Value attribute pairs eg. "priority=high", "moreInfo=..."'
        )
        parser_send.add_argument(
            '-O',
            '--origin',
            default=None,
            help='Origin of alert. Usually in form of "app/host"'
        )
        parser_send.add_argument(
            '--type',
            dest='event_type',
            default='exceptionAlert',
            help='event type eg. "exceptionAlert", "serviceAlert"'
        )
        parser_send.add_argument(
            '--timeout',
            default=None,
            help='Timeout in seconds before an "open" alert will be automatically "expired" or "deleted"'
        )
        parser_send.add_argument(
            '--raw-data',
            default=None,
            help='raw data'
        )
        parser_send.set_defaults(func=cli.send)

        parser_query = subparsers.add_parser(
            'query',
            help='List alerts based on query filter',
            usage='alerta [OPTIONS] query [--details] [--ids IDs] [--filters FILTERS]'
        )
        parser_query.add_argument(
            '--details',
            action='store_true',
            help='Show alert details'
        )
        parser_query.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_query.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_query.set_defaults(func=cli.query)

        parser_watch = subparsers.add_parser(
            'watch',
            help='Watch alerts based on query filter',
            usage='alerta [OPTIONS] watch [--ids IDs] [--filters FILTERS]'
        )
        parser_watch.add_argument(
            '--details',
            action='store_true',
            help='Show alert details'
        )
        parser_watch.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_watch.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_watch.set_defaults(func=cli.watch)

        parser_top = subparsers.add_parser(
            'top',
            help='Show top offenders and stats',
            usage='alerta [OPTIONS] top [-h]'
        )
        parser_top.set_defaults(func=cli.top)

        parser_raw = subparsers.add_parser(
            'raw',
            help='Show alert raw data',
            usage='alerta [OPTIONS] raw [--ids IDs] [--filters FILTERS]'
        )
        parser_raw.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_raw.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_raw.set_defaults(func=cli.raw)

        parser_history = subparsers.add_parser(
            'history',
            help='Show alert history',
            usage='alerta [OPTIONS] history [--ids IDs] [--filters FILTERS]'
        )
        parser_history.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_history.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_history.set_defaults(func=cli.history)

        parser_tag = subparsers.add_parser(
            'tag',
            help='Tag alerts',
            usage='alerta [OPTIONS] tag -T TAG [--ids IDs] [--filters FILTERS]'
        )
        parser_tag.add_argument(
            '-T',
            '--tag',
            metavar='TAG',
            action='append',
            dest='tags',
            required=True,
            default=list(),
            help='List of tags eg. "London", "os:linux", "AWS/EC2".'
        )
        parser_tag.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_tag.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_tag.set_defaults(func=cli.tag)

        parser_untag = subparsers.add_parser(
            'untag',
            help='Remove tags from alerts',
            usage='alerta [OPTIONS] untag -T TAG [--ids IDs] [--filters FILTERS]'
        )
        parser_untag.add_argument(
            '-T',
            '--tag',
            metavar='TAG',
            action='append',
            dest='tags',
            required=True,
            default=list(),
            help='List of tags eg. "London", "os:linux", "AWS/EC2".'
        )
        parser_untag.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            default=list(),
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_untag.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_untag.set_defaults(func=cli.untag)

        parser_ack = subparsers.add_parser(
            'ack',
            help='Acknowledge alerts',
            usage='alerta [OPTIONS] ack [--ids IDs] [--filters FILTERS]'
        )
        parser_ack.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_ack.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_ack.set_defaults(func=cli.ack)

        parser_unack = subparsers.add_parser(
            'unack',
            help='Unacknowledge alerts',
            usage='alerta [OPTIONS] unack [--ids IDs] [--filters FILTERS]'
        )
        parser_unack.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_unack.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_unack.set_defaults(func=cli.unack)

        parser_close = subparsers.add_parser(
            'close',
            help='Close alerts',
            usage='alerta [OPTIONS] close [--ids IDs] [--filters FILTERS]'
        )
        parser_close.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            default=list(),
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_close.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_close.set_defaults(func=cli.close)

        parser_delete = subparsers.add_parser(
            'delete',
            help='Delete alerts',
            usage='alerta [OPTIONS] delete [--ids IDs] [--filters FILTERS]'
        )
        parser_delete.add_argument(
            '-i',
            '--ids',
            metavar='IDs',
            nargs='+',
            default=list(),
            help='List of alert IDs (can use short 8-char id).'
        )
        parser_delete.add_argument(
            '--filters',
            nargs='+',
            default=list(),
            help='KEY=VALUE eg. serverity=warning resource=web'
        )
        parser_delete.set_defaults(func=cli.delete)

        parser_heartbeat = subparsers.add_parser(
            'heartbeat',
            help='Send heartbeat to server',
            usage='alerta [OPTIONS] heartbeat [-T TAG] [-O ORIGIN] [--timeout TIMEOUT]'
        )
        parser_heartbeat.add_argument(
            '-T',
            '--tag',
            metavar='TAG',
            action='append',
            dest='tags',
            default=list(),
            help='List of tags eg. "London", "os:linux", "AWS/EC2".'
        )
        parser_heartbeat.add_argument(
            '-O',
            '--origin',
            default=None,
            help='Origin of heartbeat. Usually in form of "app/host"'
        )
        parser_heartbeat.add_argument(
            '--timeout',
            default=None,
            help='Timeout in seconds before a heartbeat will be considered stale'
        )
        parser_heartbeat.set_defaults(func=cli.heartbeat)

        parser_status = subparsers.add_parser(
            'status',
            help='Show status and metrics',
            usage='alerta [OPTIONS] status [-h]'
        )
        parser_status.set_defaults(func=cli.status)

        parser_uptime = subparsers.add_parser(
            'uptime',
            help='Show server uptime',
            usage='alerta [OPTIONS] uptime [-h]'
        )
        parser_uptime.set_defaults(func=cli.uptime)

        parser_version = subparsers.add_parser(
            'version',
            help='Show alerta version info',
            add_help=False
        )
        parser_version.set_defaults(func=cli.version)

        parser_help = subparsers.add_parser(
            'help',
            help='Show this help',
            add_help=False
        )
        parser_help.set_defaults(func=cli.help)

        args = parser.parse_args()

        if args.func == cli.help:
            parser.print_help()
            sys.exit(0)

        if args.debug:
            root.setLevel(logging.DEBUG)
            LOG.setLevel(logging.DEBUG)
            LOG.debug("Alerta cli version: %s", __version__)

        if hasattr(args, 'ids') and args.ids:
            args.filters += ['id='+i for i in args.ids]
        args.output = 'json' if args.json else args.output

        cli.set(endpoint=args.endpoint, key=args.key)

        args.func(args)


def main():

    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Only mangle the terminal if using Python 2.x
    if sys.version_info[0] == 2:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout)

    try:
        AlertaShell().run()
    except (SystemExit, KeyboardInterrupt):
        LOG.warning("Exiting alerta client.")
        sys.exit(0)
    except Exception as e:
        LOG.error(e, exc_info=1)
        sys.exit(1)

if __name__ == "__main__":
    main()
