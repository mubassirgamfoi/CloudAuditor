"""
Explain command for CloudAuditor CLI - uses OpenAI to explain findings.
"""

import os
import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from cloudauditor.utils.logger import get_logger, setup_logging
from cloudauditor.utils.fileio import load_results, load_config

console = Console()


def explain_command(
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Filter by provider (aws or gcp)"),
    input_file: Optional[str] = typer.Option(None, "--input-file", "-i", help="Load specific results file"),
    finding_id: Optional[int] = typer.Option(None, "--finding", "-f", help="Explain specific finding by ID"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
):
    """
    Use AI to explain compliance findings in natural language.

    This command uses OpenAI's API to provide detailed explanations of security findings.
    Set your OpenAI API key in .env file or via config:
        cloudauditor config --set openai_api_key=sk-...

    Examples:
        cloudauditor explain --provider aws
        cloudauditor explain --finding 1
    """
    setup_logging(verbose)
    logger = get_logger(__name__, verbose)

    console.print(f"\n[bold cyan]CloudAuditor AI Explain[/bold cyan]\n")

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
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error loading results:[/red] {e}")
        logger.exception("Failed to load results")
        raise typer.Exit(code=1)

    findings = results.get('findings', [])

    if not findings:
        console.print("[yellow]No findings to explain.[/yellow]")
        raise typer.Exit(code=0)

    # Get OpenAI API key
    api_key = _get_openai_api_key()

    if not api_key:
        console.print("[red]Error:[/red] OpenAI API key not found.")
        console.print("\nSet your API key using one of these methods:")
        console.print("1. Environment variable: [bold]export OPENAI_API_KEY=sk-...[/bold]")
        console.print("2. .env file: [bold]OPENAI_API_KEY=sk-...[/bold]")
        console.print("3. Config: [bold]cloudauditor config --set openai_api_key=sk-...[/bold]")
        raise typer.Exit(code=1)

    # Explain specific finding or all findings
    try:
        if finding_id is not None:
            if finding_id < 1 or finding_id > len(findings):
                console.print(f"[red]Error:[/red] Invalid finding ID. Must be between 1 and {len(findings)}")
                raise typer.Exit(code=1)

            finding = findings[finding_id - 1]
            explanation = _explain_finding(finding, api_key, results.get('provider'))

            console.print(f"\n[bold]Finding #{finding_id}: {finding.get('title')}[/bold]\n")
            console.print(Panel(Markdown(explanation), title="AI Explanation", border_style="cyan"))

        else:
            # Explain summary of all findings
            explanation = _explain_summary(results, api_key)

            console.print(Panel(Markdown(explanation), title="AI Summary", border_style="cyan"))

    except ImportError:
        console.print("[red]Error:[/red] OpenAI library not installed.")
        console.print("Install it with: [bold]pip install openai[/bold]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error generating explanation:[/red] {e}")
        logger.exception("Explanation failed")
        raise typer.Exit(code=1)

    console.print("\n[green]Explanation generated successfully![/green]")


def _get_openai_api_key() -> Optional[str]:
    """
    Get OpenAI API key from various sources.

    Returns:
        API key or None if not found
    """
    # Try environment variable first
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        return api_key

    # Try .env file
    env_file = Path(".env")
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv()
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                return api_key
        except ImportError:
            pass

    # Try config file
    try:
        config = load_config()
        api_key = config.get("openai_api_key")
        if api_key:
            return api_key
    except:
        pass

    return None


def _explain_finding(finding: dict, api_key: str, provider: Optional[str] = None) -> str:
    """
    Generate AI explanation for a specific finding.

    Args:
        finding: Finding dictionary
        api_key: OpenAI API key
        provider: Cloud provider name

    Returns:
        Explanation text
    """
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        prompt = f"""You are a cloud security expert. Explain the following security finding in simple terms:

Provider: {provider or 'Unknown'}
Title: {finding.get('title')}
Severity: {finding.get('severity')}
Status: {finding.get('status')}
Resource: {finding.get('resource_id')}
Description: {finding.get('description')}
Recommendation: {finding.get('recommendation')}

Please provide:
1. What this finding means
2. Why it's important
3. Potential security risks
4. Step-by-step remediation guide

Keep the explanation clear and actionable."""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful cloud security expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.7,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Error generating explanation: {e}"


def _explain_summary(results: dict, api_key: str) -> str:
    """
    Generate AI explanation for scan summary.

    Args:
        results: Full scan results
        api_key: OpenAI API key

    Returns:
        Summary explanation text
    """
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        summary = results.get('summary', {})
        findings = results.get('findings', [])

        # Get top 5 critical/high severity findings
        critical_findings = [
            f for f in findings
            if f.get('severity', '').upper() in ['CRITICAL', 'HIGH'] and f.get('status') == 'FAILED'
        ][:5]

        findings_text = "\n".join([
            f"- {f.get('title')} (Severity: {f.get('severity')}, Resource: {f.get('resource_id')})"
            for f in critical_findings
        ])

        prompt = f"""You are a cloud security expert. Analyze this security scan summary:

Provider: {results.get('provider', 'Unknown').upper()}
Region: {results.get('region', 'Unknown')}
Total Checks: {summary.get('total_checks', 0)}
Passed: {summary.get('passed', 0)}
Failed: {summary.get('failed', 0)}
Warnings: {summary.get('warnings', 0)}

Top Critical/High Findings:
{findings_text or 'None'}

Provide:
1. Overall security posture assessment
2. Key areas of concern
3. Prioritized recommendations
4. Next steps

Keep it concise and actionable."""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful cloud security expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=600,
            temperature=0.7,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Error generating summary: {e}"
