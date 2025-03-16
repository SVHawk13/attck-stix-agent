from typer import Typer

from attck_stix_agent.api import serve_api

cli = Typer()

cli.command("serve")(serve_api)


def run_cli() -> None:
    cli()
