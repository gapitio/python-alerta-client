import click


@click.command('fire_delayed_notifications', short_help='Fire delayed notifications')
@click.pass_obj
def cli(obj):
    """Firing delayed notification rules"""
    client = obj['client']
    client.fire_delayed_notifications()
