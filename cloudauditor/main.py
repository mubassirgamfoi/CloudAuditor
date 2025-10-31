"""
Main entry point for the CloudAuditor CLI application.
"""

import typer
from typing import Optional
from rich.console import Console

from cloudauditor import __version__
from cloudauditor.commands import scan, report, config, explain

# Initialize Typer app
app = typer.Typer(
    name="cloudauditor",
    help="Cloud Security Compliance Scanner for AWS and GCP",
    add_completion=False,
)

# Initialize Rich console
console = Console()

# Register subcommands
app.command(name="scan")(scan.scan_command)
app.command(name="report")(report.report_command)
app.command(name="config")(config.config_command)
app.command(name="explain")(explain.explain_command)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        is_eager=True,
    ),
):
    """
    CloudAuditor - Multi-cloud security compliance scanner.

    Scan AWS and GCP environments for CIS benchmark compliance issues
    and security misconfigurations.
    """
    if version:
        console.print(f"[bold cyan]CloudAuditor[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print("[yellow]Welcome to CloudAuditor![/yellow]")
        console.print("\nUse [bold]cloudauditor --help[/bold] to see available commands.")
        raise typer.Exit()


if __name__ == "__main__":
    app()
