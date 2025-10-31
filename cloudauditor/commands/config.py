"""
Config command for CloudAuditor CLI.
"""

import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cloudauditor.utils.logger import get_logger, setup_logging
from cloudauditor.utils.fileio import load_config, save_config, get_config_dir

console = Console()


def config_command(
    show: bool = typer.Option(False, "--show", "-s", help="Show current configuration"),
    provider: Optional[str] = typer.Option(None, "--provider", help="Provider to configure (aws or gcp)"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Set default profile/project"),
    region: Optional[str] = typer.Option(None, "--region", help="Set default region"),
    set_key: Optional[str] = typer.Option(None, "--set", help="Set custom config key (format: key=value)"),
    reset: bool = typer.Option(False, "--reset", help="Reset configuration to defaults"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
):
    """
    Manage CloudAuditor configuration settings.

    Configuration is stored in ~/.cloudauditor/config.yaml

    Examples:
        cloudauditor config --show
        cloudauditor config --provider aws --profile prod --region us-east-1
        cloudauditor config --provider gcp --profile my-project --region us-central1
        cloudauditor config --set openai_api_key=sk-...
        cloudauditor config --reset
    """
    setup_logging(verbose)
    logger = get_logger(__name__, verbose)

    config_file = get_config_dir() / "config.yaml"

    # Show configuration
    if show:
        try:
            config = load_config()

            if not config:
                console.print("\n[yellow]No configuration found.[/yellow]")
                console.print(f"Config file location: [dim]{config_file}[/dim]")
                console.print("\nUse [bold]cloudauditor config --provider <provider> --profile <profile>[/bold] to set defaults.")
                raise typer.Exit(code=0)

            console.print(f"\n[bold cyan]CloudAuditor Configuration[/bold cyan]")
            console.print(f"Location: [dim]{config_file}[/dim]\n")

            # Create table for provider configs
            for provider_name in ["aws", "gcp"]:
                if provider_name in config:
                    table = Table(title=f"{provider_name.upper()} Configuration", show_header=True, header_style="bold magenta")
                    table.add_column("Setting", style="cyan")
                    table.add_column("Value", style="yellow")

                    for key, value in config[provider_name].items():
                        table.add_row(key, str(value))

                    console.print(table)
                    console.print()

            # Show other settings
            other_settings = {k: v for k, v in config.items() if k not in ["aws", "gcp"]}
            if other_settings:
                table = Table(title="Other Settings", show_header=True, header_style="bold magenta")
                table.add_column("Setting", style="cyan")
                table.add_column("Value", style="yellow")

                for key, value in other_settings.items():
                    # Mask sensitive values
                    if "key" in key.lower() or "secret" in key.lower() or "token" in key.lower():
                        value = "***" + str(value)[-4:] if value else "not set"
                    table.add_row(key, str(value))

                console.print(table)

            raise typer.Exit(code=0)

        except Exception as e:
            console.print(f"[red]Error showing configuration:[/red] {e}")
            logger.exception("Failed to show config")
            raise typer.Exit(code=1)

    # Reset configuration
    if reset:
        try:
            if config_file.exists():
                config_file.unlink()
                console.print("[green]Configuration reset successfully.[/green]")
            else:
                console.print("[yellow]No configuration to reset.[/yellow]")
            raise typer.Exit(code=0)
        except Exception as e:
            console.print(f"[red]Error resetting configuration:[/red] {e}")
            logger.exception("Failed to reset config")
            raise typer.Exit(code=1)

    # Update configuration
    try:
        config = load_config()

        if set_key:
            # Set custom key-value pair
            if "=" not in set_key:
                console.print("[red]Error:[/red] Invalid format. Use --set key=value")
                raise typer.Exit(code=1)

            key, value = set_key.split("=", 1)
            config[key.strip()] = value.strip()
            console.print(f"[green]Set {key.strip()} = {value.strip()}[/green]")

        if provider:
            # Validate provider
            provider = provider.lower()
            if provider not in ["aws", "gcp"]:
                console.print(f"[red]Error:[/red] Unsupported provider: {provider}")
                console.print("Supported providers: aws, gcp")
                raise typer.Exit(code=1)

            # Initialize provider config if not exists
            if provider not in config:
                config[provider] = {}

            # Update provider settings
            if profile:
                if provider == "aws":
                    config[provider]["profile"] = profile
                else:  # gcp
                    config[provider]["project"] = profile
                console.print(f"[green]Set {provider.upper()} profile/project: {profile}[/green]")

            if region:
                config[provider]["region"] = region
                console.print(f"[green]Set {provider.upper()} region: {region}[/green]")

        # Save configuration
        if provider or set_key:
            save_config(config)
            console.print(f"\n[green]Configuration saved to:[/green] {config_file}")
        else:
            console.print("[yellow]No changes made.[/yellow]")
            console.print("Use [bold]--help[/bold] to see available options.")

    except Exception as e:
        console.print(f"[red]Error updating configuration:[/red] {e}")
        logger.exception("Failed to update config")
        raise typer.Exit(code=1)
