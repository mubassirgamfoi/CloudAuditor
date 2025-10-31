"""
Output formatting utilities for CloudAuditor.
"""

import json
import html as html_escape_mod
from typing import Dict, List, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


def format_output(data: Dict[str, Any], output_format: str = "json") -> str:
    """
    Format scan results into the specified output format.

    Args:
        data: Scan results dictionary
        output_format: Output format (json, markdown, html)

    Returns:
        Formatted string output
    """
    if output_format == "json":
        return format_json(data)
    elif output_format == "markdown":
        return format_markdown(data)
    elif output_format == "html":
        return format_html(data)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def format_json(data: Dict[str, Any]) -> str:
    """Format data as JSON."""
    return json.dumps(data, indent=2, default=str)


def format_markdown(data: Dict[str, Any]) -> str:
    """Format data as Markdown with detailed context and remediation."""
    lines: List[str] = []

    # Header and scan context
    lines.append("# CloudAuditor Compliance Report")
    lines.append("")
    lines.append(f"**Generated:** {data.get('timestamp', datetime.now().isoformat())}")
    lines.append(f"**Provider:** {data.get('provider', 'N/A').upper()}")
    if data.get('region') is not None:
        lines.append(f"**Region:** {data.get('region', 'N/A')}")
    if data.get('profile') is not None:
        lines.append(f"**Profile/Project:** {data.get('profile')}")
    if data.get('project_id') is not None:
        lines.append(f"**Project ID:** {data.get('project_id')}")

    # Overall CLI command (if captured)
    scan_ctx = data.get('scan_context') or {}
    if scan_ctx.get('cli_command'):
        lines.append(f"**Command:** `{scan_ctx.get('cli_command')}`")

    # Compliance standards executed
    standards = data.get('compliance_standards') or []
    if standards:
        lines.append("")
        lines.append("## Benchmarks Executed")
        for std in standards:
            lines.append(f"- {std}")

    # Summary block
    lines.append("")
    lines.append("## Summary")
    summary = data.get('summary', {})
    lines.append(f"- **Total Checks:** {summary.get('total', summary.get('total_checks', 0))}")
    lines.append(f"- **Passed:** {summary.get('passed', 0)}")
    lines.append(f"- **Failed:** {summary.get('failed', 0)}")
    lines.append(f"- **Warnings:** {summary.get('warnings', 0)}")

    # Findings
    lines.append("")
    lines.append("## Findings")
    findings: List[Dict[str, Any]] = data.get('findings', [])

    if not findings:
        lines.append("No findings detected.")
        return "\n".join(lines)

    for i, finding in enumerate(findings, 1):
        title = finding.get('title', 'Untitled Finding')
        check_id = finding.get('check_id') or finding.get('id') or "N/A"
        severity = (finding.get('severity') or 'INFO').upper()
        status = (finding.get('status') or 'UNKNOWN').upper()
        resource = finding.get('resource_id', 'N/A')
        description = finding.get('description', 'No description provided')
        recommendation = finding.get('recommendation')
        compliance = finding.get('compliance_standard') or finding.get('compliance')
        region = finding.get('region') or data.get('region') or 'global'
        evidence = finding.get('evidence') or finding.get('details')

        lines.append("")
        lines.append(f"### {i}. {title}")
        lines.append(f"- **Check ID:** `{check_id}`")
        lines.append(f"- **Severity:** {severity}")
        lines.append(f"- **Status:** {status}")
        lines.append(f"- **Resource:** `{resource}`")
        lines.append(f"- **Region:** {region}")
        if compliance:
            lines.append(f"- **Compliance:** {compliance}")
        lines.append("")
        lines.append(f"**Description:** {description}")
        if recommendation:
            lines.append("")
            # Render recommendation with fenced code blocks for any CLI lines
            lines.append("**Recommendation (CIS):**")
            # Normalize escaped newlines to real newlines for readability
            rec_str = str(recommendation).replace("\\n", "\n")
            rec_lines = rec_str.splitlines() if "\n" in rec_str else [rec_str]
            cmd_lines: List[str] = []
            prose_lines: List[str] = []
            prefixes = ("aws ", "gcloud ", "az ", "doctl ", "kubectl ", "terraform ", "curl ")
            for rl in rec_lines:
                rl_strip = rl.strip()
                # Detect inline commands anywhere in the line
                idxs = [rl_strip.find(p) for p in prefixes if rl_strip.find(p) != -1]
                if rl_strip.startswith("$"):
                    cmd_lines.append(rl_strip[2:])
                elif idxs:
                    first_idx = min(idxs)
                    if first_idx > 0:
                        prose_segment = rl_strip[:first_idx].rstrip()
                        if prose_segment:
                            prose_lines.append(prose_segment)
                    command_segment = rl_strip[first_idx:]
                    # split multiple commands separated by ';'
                    for part in [p.strip() for p in command_segment.split(";")]:
                        if any(part.startswith(pref) for pref in prefixes):
                            cmd_lines.append(part)
                else:
                    prose_lines.append(rl)
            if prose_lines:
                lines.append("\n".join(prose_lines))
            if cmd_lines:
                lines.append("")
                lines.append("```bash")
                lines.append("\n".join(cmd_lines))
                lines.append("```")
        # Always show per-finding command and evidence
        provider_upper = (data.get('provider') or '').upper()
        default_cmd = {
            'AWS': 'aws <service> <describe|get> ... --output json',
            'GCP': 'gcloud <service> <describe|get> ... --format=json',
            'AZURE': 'az <resource> show/list --output json',
            'DIGITALOCEAN': 'doctl <resource> <get|list> --output json',
        }.get(provider_upper, '<cli> <resource> <get|describe>')
        cmd = finding.get('command') or finding.get('command_executed') or default_cmd
        lines.append("")
        lines.append("**Command Executed:**")
        lines.append("")
        lines.append(f"```bash\n{cmd}\n```")
        lines.append("")
        lines.append("**Evidence/Output:**")
        lines.append("")
        # Pretty-print JSON evidence where possible
        if isinstance(evidence, (dict, list)):
            try:
                ev_str = json.dumps(evidence, indent=2, default=str)
            except Exception:
                ev_str = str(evidence)
            lines.append(f"```json\n{ev_str}\n```")
        else:
            ev_str = (str(evidence).strip() if evidence is not None else 'No evidence provided')
            lines.append(f"```bash\n{ev_str}\n```")
        lines.append("")
        lines.append("---")

    return "\n".join(lines)


def format_html(data: Dict[str, Any]) -> str:
    """Format data as HTML with detailed context and remediation."""
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html>")
    html.append("<head>")
    html.append("<meta charset='UTF-8'>")
    html.append("<title>CloudAuditor Compliance Report</title>")
    html.append("<style>")
    html.append("""
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background-color: #f9f9f9; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .summary-item { display: inline-block; margin: 10px 20px 10px 0; }
        .finding { border-left: 4px solid #ff9800; padding: 15px; margin: 15px 0; background-color: #fafafa; }
        .finding.CRITICAL { border-left-color: #f44336; }
        .finding.HIGH { border-left-color: #ff5722; }
        .finding.MEDIUM { border-left-color: #ff9800; }
        .finding.LOW { border-left-color: #ffc107; }
        .finding.INFO { border-left-color: #2196F3; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .badge.FAILED { background-color: #f44336; color: white; }
        .badge.PASSED { background-color: #4CAF50; color: white; }
        .badge.WARNING { background-color: #ff9800; color: white; }
        .resource { font-family: monospace; background-color: #eee; padding: 2px 6px; border-radius: 3px; }
        .meta { color: #666; font-size: 14px; }
        pre { background: #2e3440; color: #eceff4; padding: 12px; border-radius: 6px; overflow-x: auto; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 13px; }
    """)
    html.append("</style>")
    # Syntax highlighting (highlight.js)
    html.append("<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css\">")
    html.append("<script src=\"https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js\"></script>")
    html.append("<script>document.addEventListener('DOMContentLoaded',()=>{try{hljs.highlightAll()}catch(e){}});</script>")
    html.append("</head>")
    html.append("<body>")
    html.append("<div class='container'>")

    html.append("<h1>CloudAuditor Compliance Report</h1>")
    html.append(f"<p class='meta'>Generated: {data.get('timestamp', datetime.now().isoformat())}</p>")
    provider = data.get('provider', 'N/A').upper()
    region = data.get('region', 'N/A')
    profile = data.get('profile', 'default')
    project_id = data.get('project_id')
    meta_parts = [f"Provider: <strong>{provider}</strong>", f"Region: <strong>{region}</strong>", f"Profile: <strong>{profile}</strong>"]
    if project_id:
        meta_parts.append(f"Project ID: <strong>{project_id}</strong>")
    html.append(f"<p class='meta'>{' | '.join(meta_parts)}</p>")

    # Benchmarks executed
    standards = data.get('compliance_standards') or []
    if standards:
        html.append("<h2>Benchmarks Executed</h2>")
        html.append("<ul>")
        for std in standards:
            html.append(f"<li>{std}</li>")
        html.append("</ul>")

    html.append("<div class='summary'>")
    html.append("<h2>Summary</h2>")
    summary = data.get('summary', {})
    html.append(f"<div class='summary-item'><strong>Total Checks:</strong> {summary.get('total', summary.get('total_checks', 0))}</div>")
    html.append(f"<div class='summary-item'><strong>Passed:</strong> {summary.get('passed', 0)}</div>")
    html.append(f"<div class='summary-item'><strong>Failed:</strong> {summary.get('failed', 0)}</div>")
    html.append(f"<div class='summary-item'><strong>Warnings:</strong> {summary.get('warnings', 0)}</div>")
    html.append("</div>")

    # Filters UI
    html.append("<h2>Findings</h2>")
    html.append("""
    <div style='margin: 10px 0 20px 0;'>
      <label for='filterName'><strong>Filter by name:</strong></label>
      <input id='filterName' type='text' placeholder='Search title or check id' style='margin-right:10px;padding:6px;'>
      <label for='filterStatus'><strong>Status:</strong></label>
      <select id='filterStatus' style='padding:6px;'>
        <option value='ALL'>All</option>
        <option value='PASSED'>Passed</option>
        <option value='FAILED'>Failed</option>
        <option value='WARNING'>Warning</option>
      </select>
    </div>
    """)
    findings = data.get('findings', [])

    if not findings:
        html.append("<p>No findings detected.</p>")
    else:
        for finding in findings:
            severity = (finding.get('severity') or 'INFO').upper()
            status = (finding.get('status') or 'UNKNOWN').upper()
            title = finding.get('title', 'Untitled Finding')
            check_id = finding.get('check_id') or finding.get('id') or 'N/A'
            resource = finding.get('resource_id', 'N/A')
            description = finding.get('description', 'No description')
            recommendation = finding.get('recommendation')
            compliance = finding.get('compliance_standard') or finding.get('compliance')
            freg = finding.get('region') or region
            evidence = finding.get('evidence') or finding.get('details')
            provider_upper = provider
            default_cmd = {
                'AWS': 'aws <service> <describe|get> ... --output json',
                'GCP': 'gcloud <service> <describe|get> ... --format=json',
                'AZURE': 'az <resource> show/list --output json',
                'DIGITALOCEAN': 'doctl <resource> <get|list> --output json',
            }.get(provider_upper, '<cli> <resource> <get|describe>')
            cmd = finding.get('command') or finding.get('command_executed') or default_cmd

            html.append(f"<div class='finding {severity}' data-title='{(title + ' ' + str(check_id)).lower()}' data-status='{status}'>")
            html.append(f"<h3>{title}</h3>")
            html.append(f"<p><span class='badge {status}'>{status}</span> <strong>Severity:</strong> {severity} | <strong>Check ID:</strong> <code>{check_id}</code></p>")
            html.append(f"<p><strong>Resource:</strong> <span class='resource'>{resource}</span> | <strong>Region:</strong> {freg}</p>")
            if compliance:
                html.append(f"<p><strong>Compliance:</strong> {compliance}</p>")
            html.append(f"<p>{description}</p>")
            if recommendation:
                # Split recommendation into prose and command lines
                rec_str = str(recommendation).replace("\\n", "\n")
                rec_lines = rec_str.splitlines() if "\n" in rec_str else [rec_str]
                cmd_lines = []
                prose_lines = []
                prefixes = ("aws ", "gcloud ", "az ", "doctl ", "kubectl ", "terraform ", "curl ")
                for rl in rec_lines:
                    rl_strip = rl.strip()
                    idxs = [rl_strip.find(p) for p in prefixes if rl_strip.find(p) != -1]
                    if rl_strip.startswith("$"):
                        cmd_lines.append(rl_strip[2:])
                    elif idxs:
                        first_idx = min(idxs)
                        if first_idx > 0:
                            prose_segment = rl_strip[:first_idx].rstrip()
                            if prose_segment:
                                prose_lines.append(prose_segment)
                        command_segment = rl_strip[first_idx:]
                        for part in [p.strip() for p in command_segment.split(";")]:
                            if any(part.startswith(pref) for pref in prefixes):
                                cmd_lines.append(part)
                    else:
                        prose_lines.append(rl)
                if prose_lines:
                    # Preserve line breaks in prose
                    escaped_lines = [html_escape_mod.escape(x) for x in prose_lines]
                    html.append(f"<p><strong>Recommendation (CIS):</strong> {'<br>'.join(escaped_lines)}</p>")
                if cmd_lines:
                    html.append("<p><strong>Recommendation Commands:</strong></p>")
                    html.append("<pre><code class=\"language-bash\">")
                    html.append(html_escape_mod.escape("\n".join(cmd_lines)))
                    html.append("</code></pre>")
            html.append("<p><strong>Command Executed:</strong></p>")
            # Choose language for command highlighting
            lang = 'bash'
            cmd_str = str(cmd)
            html.append(f"<pre><code class=\"language-{lang}\">")
            html.append(html_escape_mod.escape(cmd_str))
            html.append("</code></pre>")

            # Evidence block
            ev_lang = 'json' if isinstance(evidence, (dict, list)) else 'bash'
            if isinstance(evidence, (dict, list)):
                try:
                    ev_str = json.dumps(evidence, indent=2, default=str)
                except Exception:
                    ev_str = str(evidence)
            else:
                ev_str = str(evidence) if evidence is not None else 'No evidence provided'
            html.append("<p><strong>Evidence/Output:</strong></p>")
            html.append(f"<pre><code class=\"language-{ev_lang}\">")
            html.append(html_escape_mod.escape(ev_str))
            html.append("</code></pre>")
            html.append("</div>")

    html.append("</div>")
    # Filtering script
    html.append("""
    <script>
      (function(){
        const nameInput = document.getElementById('filterName');
        const statusSelect = document.getElementById('filterStatus');
        function applyFilter(){
          const q = (nameInput.value || '').toLowerCase();
          const st = statusSelect.value;
          const items = document.querySelectorAll('.finding');
          items.forEach(el => {
            const title = el.getAttribute('data-title') || '';
            const status = el.getAttribute('data-status') || '';
            const matchesName = !q || title.indexOf(q) !== -1;
            const matchesStatus = (st === 'ALL') || (status === st);
            el.style.display = (matchesName && matchesStatus) ? '' : 'none';
          });
        }
        nameInput && nameInput.addEventListener('input', applyFilter);
        statusSelect && statusSelect.addEventListener('change', applyFilter);
      })();
    </script>
    """)
    html.append("</body>")
    html.append("</html>")

    return "\n".join(html)


def display_scan_results(data: Dict[str, Any]) -> None:
    """
    Display scan results in a rich table format on the console.

    Args:
        data: Scan results dictionary
    """
    console.print()

    # Create summary panel
    summary = data.get('summary', {})
    summary_text = f"""
[bold]Provider:[/bold] {data.get('provider', 'N/A').upper()}
[bold]Region:[/bold] {data.get('region', 'N/A')}
[bold]Profile:[/bold] {data.get('profile', 'default')}

[bold cyan]Total Checks:[/bold cyan] {summary.get('total_checks', 0)}
[bold green]Passed:[/bold green] {summary.get('passed', 0)}
[bold red]Failed:[/bold red] {summary.get('failed', 0)}
[bold yellow]Warnings:[/bold yellow] {summary.get('warnings', 0)}
    """

    console.print(Panel(summary_text.strip(), title="[bold]Scan Summary[/bold]", border_style="cyan"))

    # Create findings table
    findings = data.get('findings', [])

    if findings:
        table = Table(title="\nFindings", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Severity", width=10)
        table.add_column("Status", width=10)
        table.add_column("Title", width=40)
        table.add_column("Resource", width=30)

        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'INFO').upper()
            status = finding.get('status', 'UNKNOWN').upper()

            # Color code severity
            severity_colors = {
                'CRITICAL': 'bold red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'blue',
                'INFO': 'cyan'
            }
            severity_styled = f"[{severity_colors.get(severity, 'white')}]{severity}[/]"

            # Color code status
            status_colors = {
                'FAILED': 'bold red',
                'PASSED': 'bold green',
                'WARNING': 'bold yellow'
            }
            status_styled = f"[{status_colors.get(status, 'white')}]{status}[/]"

            table.add_row(
                str(i),
                severity_styled,
                status_styled,
                finding.get('title', 'N/A'),
                finding.get('resource_id', 'N/A')
            )

        console.print(table)
    else:
        console.print("\n[green]No findings detected. All checks passed![/green]")

    console.print()
