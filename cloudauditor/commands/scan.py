"""
Scan command for CloudAuditor CLI.
"""

import typer
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from cloudauditor.providers import AWSScanner, GCPScanner, AzureScanner, DigitalOceanScanner
from cloudauditor.utils.logger import get_logger, setup_logging
from cloudauditor.utils.formatter import format_output, display_scan_results
from cloudauditor.utils.fileio import save_results, save_output, load_config

console = Console()


def scan_command(
    provider: str = typer.Argument(..., help="Cloud provider to scan (aws, gcp, azure, or digitalocean)"),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Cloud provider profile/project/subscription"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Cloud provider region"),
    tenant: Optional[str] = typer.Option(None, "--tenant", "-t", help="Azure tenant ID"),
    output: str = typer.Option("json", "--output", "-o", help="Output format (json, markdown, html)"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Save output to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
):
    """
    Scan cloud environment for CIS benchmark compliance issues.

    Examples:
        cloudauditor scan aws --profile prod --region us-east-1 --output json
        cloudauditor scan gcp --profile my-project --output markdown
        cloudauditor scan azure --profile subscription-id --tenant tenant-id --output json
    """
    setup_logging(verbose)
    logger = get_logger(__name__, verbose)

    # Validate provider
    provider = provider.lower()
    if provider not in ["aws", "gcp", "azure", "digitalocean"]:
        console.print(f"[red]Error:[/red] Unsupported provider: {provider}")
        console.print("Supported providers: aws, gcp, azure, digitalocean")
        raise typer.Exit(code=1)

    # Validate output format
    output = output.lower()
    if output not in ["json", "markdown", "html"]:
        console.print(f"[red]Error:[/red] Unsupported output format: {output}")
        console.print("Supported formats: json, markdown, html")
        raise typer.Exit(code=1)

    # Load config to get defaults
    config = load_config()
    provider_config = config.get(provider, {})

    # Use config defaults if not provided
    if profile is None:
        profile = provider_config.get('profile') or provider_config.get('project') or provider_config.get('subscription')
    if region is None:
        region = provider_config.get('region')
    if tenant is None and provider == "azure":
        tenant = provider_config.get('tenant')

    console.print(f"\n[bold cyan]CloudAuditor Security Scan[/bold cyan]")
    console.print(f"Provider: [yellow]{provider.upper()}[/yellow]")
    console.print(f"Profile: [yellow]{profile or 'default'}[/yellow]")
    console.print(f"Region: [yellow]{region or 'default'}[/yellow]")
    if provider == "azure" and tenant:
        console.print(f"Tenant: [yellow]{tenant}[/yellow]")
    # Default to real API mode
    console.print("")

    # Initialize scanner based on provider
    try:
        # Use simpler progress display for Windows console compatibility
        import sys
        import platform
        use_fancy_progress = not (platform.system() == "Windows" and sys.stdout.encoding in ['cp1252', 'cp437'])

        if use_fancy_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"Scanning {provider.upper()} environment...", total=None)

                if provider == "aws":
                    scanner = AWSScanner(
                        profile=profile,
                        region=region,
                        use_mock=False
                    )
                elif provider == "gcp":
                    scanner = GCPScanner(
                        profile=profile,
                        region=region,
                        use_mock=False
                    )
                elif provider == "azure":
                    scanner = AzureScanner(
                        subscription_id=profile,
                        tenant_id=tenant,
                        use_mock=False
                    )
                elif provider == "digitalocean":
                    scanner = DigitalOceanScanner(
                        account=profile,
                        use_mock=False,
                        cli_command="cloudauditor scan digitalocean"
                    )

                # Perform scan
                results = scanner.scan()

                progress.update(task, completed=True)
        else:
            # Simple console output for Windows
            console.print(f"[cyan]Scanning {provider.upper()} environment...[/cyan]")

            if provider == "aws":
                scanner = AWSScanner(
                    profile=profile,
                    region=region,
                    use_mock=False
                )
            elif provider == "gcp":
                scanner = GCPScanner(
                    profile=profile,
                    region=region,
                    use_mock=False
                )
            elif provider == "azure":
                scanner = AzureScanner(
                    subscription_id=profile,
                    tenant_id=tenant,
                    use_mock=False
                )
            elif provider == "digitalocean":
                scanner = DigitalOceanScanner(
                    account=profile,
                    use_mock=False,
                    cli_command="cloudauditor scan digitalocean"
                )

            # Perform scan
            results = scanner.scan()
            console.print(f"[green]Scan completed![/green]")

    except Exception as e:
        console.print(f"\n[red]Error during scan:[/red] {e}")
        logger.exception("Scan failed")
        raise typer.Exit(code=1)

    # Attach scan context (CLI invocation and options)
    try:
        import shlex
        argv = ["cloudauditor", "scan", provider]
        if profile:
            argv += ["--profile", profile]
        if region:
            argv += ["--region", region]
        if output:
            argv += ["--output", output]
        if output_file:
            argv += ["--output-file", output_file]
        if verbose:
            argv += ["--verbose"]
        results.setdefault('scan_context', {})['cli_command'] = " ".join(shlex.quote(a) for a in argv)
        results['scan_context']['provider'] = provider
        results['scan_context']['region'] = region
        results['scan_context']['profile'] = profile
        results['scan_context']['output'] = output
    except Exception:
        pass

    # Display results
    display_scan_results(results)

    # Save results to file
    try:
        results_file = save_results(results)
        console.print(f"[green]Results saved to:[/green] {results_file}")
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not save results: {e}")

    # Export to specified format if output file provided
    if output_file:
        try:
            formatted_output = format_output(results, output)
            from pathlib import Path
            output_path = Path(output_file)
            final_path = save_output(formatted_output, output_path, output)
            console.print(f"[green]Output exported to:[/green] {final_path}")
        except Exception as e:
            console.print(f"[red]Error exporting output:[/red] {e}")
            logger.exception("Export failed")

    # Exit with appropriate code
    failed_count = results.get('summary', {}).get('failed', 0)
    if failed_count > 0:
        console.print(f"\n[yellow]Scan completed with {failed_count} failed check(s)[/yellow]")
        raise typer.Exit(code=1)
    else:
        console.print(f"\n[green]Scan completed successfully![/green]")
        raise typer.Exit(code=0)
