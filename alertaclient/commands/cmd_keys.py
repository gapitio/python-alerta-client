
import sys
import click
import json

from tabulate import tabulate


@click.command('customers', short_help='List API keys')
@click.pass_obj
def cli(obj):
    """List API keys."""
    client = obj['client']

    if obj['output'] == 'json':
        r = client.http.get('/keys')
        click.echo(json.dumps(r['keys'], sort_keys=True, indent=4, ensure_ascii=False))
        sys.exit(0)

    timezone = obj['timezone']
    headers = {
        'id': 'ID', 'key': 'API KEY', 'user': 'USER', 'scopes': 'SCOPES', 'text': 'TEXT',
        'expireTime': 'EXPIRES', 'count': 'COUNT', 'lastUsedTime': 'LAST USED', 'customer': 'CUSTOMER'
    }
    click.echo(tabulate([k.tabular(timezone) for k in client.get_keys()], headers=headers, tablefmt=obj['output']))