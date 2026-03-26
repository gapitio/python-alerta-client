import click


@click.command('housekeeping', short_help='Expired and clears old alerts.')
@click.pass_obj
def cli(obj, expired=None, info=None):
    """Trigger the expiration and deletion of alerts."""
    client = obj['client']
    client.housekeeping()
