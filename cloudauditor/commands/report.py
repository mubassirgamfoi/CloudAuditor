"""
Report command for CloudAuditor CLI.
"""

import typer
from typing import Optional
from pathlib import Path
from rich.console import Console

from cloudauditor.utils.logger import get_logger, setup_logging
from cloudauditor.utils.formatter import format_output, display_scan_results
from cloudauditor.utils.fileio import load_results, save_output, list_results

console = Console()


def report_command(
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Filter by provider (aws or gcp)"),
    output: str = typer.Option("json", "--output", "-o", help="Output format (json, markdown, html)"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Save output to file"),
    input_file: Optional[str] = typer.Option(None, "--input-file", "-i", help="Load specific results file"),
    list_scans: bool = typer.Option(False, "--list", "-l", help="List available scan results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
):
    """
    Generate compliance report from scan results.

    Examples:
        cloudauditor report --output markdown --output-file report.md
        cloudauditor report --provider aws --output html --output-file aws-report.html
        cloudauditor report --list
    """
    setup_logging(verbose)
    logger = get_logger(__name__, verbose)

    # List available scans if requested
    if list_scans:
        console.print("\n[bold cyan]Available Scan Results[/bold cyan]\n")
        try:
            results = list_results(provider)
            if not results:
                console.print("[yellow]No scan results found.[/yellow]")
                console.print("Run a scan first: [bold]cloudauditor scan <provider>[/bold]")
                raise typer.Exit(code=0)

            for i, result_file in enumerate(results, 1):
                console.print(f"{i}. {result_file.name} ({result_file.stat().st_size} bytes)")

            console.print()
            raise typer.Exit(code=0)

        except Exception as e:
            console.print(f"[red]Error listing results:[/red] {e}")
            logger.exception("Failed to list results")
            raise typer.Exit(code=1)

    # Validate output format
    output = output.lower()
    if output not in ["json", "markdown", "html"]:
        console.print(f"[red]Error:[/red] Unsupported output format: {output}")
        console.print("Supported formats: json, markdown, html")
        raise typer.Exit(code=1)

    console.print(f"\n[bold cyan]CloudAuditor Compliance Report[/bold cyan]\n")

    # Load results
    try:
        if input_file:
            console.print(f"Loading results from: [yellow]{input_file}[/yellow]")
            results = load_results(filename=input_file)
        elif provider:
            console.print(f"Loading latest {provider.upper()} scan results...")
            results = load_results(provider=provider)
        else:
            console.print("Loading latest scan results...")
            results = load_results()

    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("\nRun a scan first: [bold]cloudauditor scan <provider>[/bold]")
        console.print("Or list available results: [bold]cloudauditor report --list[/bold]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error loading results:[/red] {e}")
        logger.exception("Failed to load results")
        raise typer.Exit(code=1)

    # Display results summary
    display_scan_results(results)

    # Format and output
    try:
        formatted_output = format_output(results, output)

        if output_file:
            # Save to file
            output_path = Path(output_file)
            save_output(formatted_output, output_path, output)
            console.print(f"\n[green]Report saved to:[/green] {output_path}")
        else:
            # Print to console
            console.print(f"\n[bold]Report ({output.upper()} format)[/bold]\n")
            console.print(formatted_output)

    except Exception as e:
        console.print(f"[red]Error generating report:[/red] {e}")
        logger.exception("Report generation failed")
        raise typer.Exit(code=1)

    console.print("\n[green]Report generated successfully![/green]")
    raise typer.Exit(code=0)
