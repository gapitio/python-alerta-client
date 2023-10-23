import click


@click.command('escalate', short_help='Escalate alerts using escaltion rules')
@click.pass_obj
def cli(obj):
    """Trigger escalation of alerts"""
    client = obj['client']
    client.escalate()
