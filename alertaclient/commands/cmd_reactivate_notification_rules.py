import click


@click.command('reactivate_notitification_rules', short_help='Reactivate inactive notification rules after reactivate time is up')
@click.pass_obj
def cli(obj):
    """Trigger reactivation of notification rules"""
    client = obj['client']
    client.reactivate_notification_rules()
