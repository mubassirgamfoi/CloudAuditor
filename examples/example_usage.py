#!/usr/bin/env python3
"""
Example usage of CloudAuditor CLI as a Python module.

This demonstrates how to use CloudAuditor programmatically
instead of through the command line.
"""

from cloudauditor.providers import AWSScanner, GCPScanner
from cloudauditor.utils.formatter import format_output, display_scan_results
from cloudauditor.utils.fileio import save_results
import json


def example_aws_scan():
    """Example: Scan AWS environment and display results."""
    print("=" * 60)
    print("AWS Security Scan Example")
    print("=" * 60)

    # Initialize scanner
    scanner = AWSScanner(
        profile="default",
        region="us-east-1",
        use_mock=True  # Set to False to use real AWS API
    )

    # Perform scan
    results = scanner.scan()

    # Display results
    display_scan_results(results)

    # Save results
    output_file = save_results(results)
    print(f"\nResults saved to: {output_file}")

    return results


def example_gcp_scan():
    """Example: Scan GCP environment and export to Markdown."""
    print("\n" + "=" * 60)
    print("GCP Security Scan Example")
    print("=" * 60)

    # Initialize scanner
    scanner = GCPScanner(
        profile="my-project",
        region="us-central1",
        use_mock=True  # Set to False to use real GCP API
    )

    # Perform scan
    results = scanner.scan()

    # Display results
    display_scan_results(results)

    # Export to Markdown
    markdown_output = format_output(results, "markdown")
    with open("gcp_report.md", "w") as f:
        f.write(markdown_output)
    print("\nMarkdown report saved to: gcp_report.md")

    return results


def example_compare_providers():
    """Example: Compare security posture across providers."""
    print("\n" + "=" * 60)
    print("Multi-Cloud Comparison Example")
    print("=" * 60)

    # Scan both providers
    aws_scanner = AWSScanner(use_mock=True)
    gcp_scanner = GCPScanner(use_mock=True)

    aws_results = aws_scanner.scan()
    gcp_results = gcp_scanner.scan()

    # Compare summaries
    print("\nSecurity Posture Comparison:")
    print("-" * 60)

    print(f"\nAWS:")
    print(f"  Total Checks: {aws_results['summary']['total_checks']}")
    print(f"  Passed: {aws_results['summary']['passed']}")
    print(f"  Failed: {aws_results['summary']['failed']}")

    print(f"\nGCP:")
    print(f"  Total Checks: {gcp_results['summary']['total_checks']}")
    print(f"  Passed: {gcp_results['summary']['passed']}")
    print(f"  Failed: {gcp_results['summary']['failed']}")

    # Calculate compliance percentage
    aws_compliance = (
        aws_results['summary']['passed'] / aws_results['summary']['total_checks'] * 100
    )
    gcp_compliance = (
        gcp_results['summary']['passed'] / gcp_results['summary']['total_checks'] * 100
    )

    print(f"\nCompliance Rates:")
    print(f"  AWS: {aws_compliance:.1f}%")
    print(f"  GCP: {gcp_compliance:.1f}%")


def example_filter_critical_findings():
    """Example: Filter and display only critical findings."""
    print("\n" + "=" * 60)
    print("Critical Findings Example")
    print("=" * 60)

    # Scan AWS
    scanner = AWSScanner(use_mock=True)
    results = scanner.scan()

    # Filter critical and high severity findings
    critical_findings = [
        f for f in results['findings']
        if f.get('severity', '').upper() in ['CRITICAL', 'HIGH']
        and f.get('status') == 'FAILED'
    ]

    print(f"\nFound {len(critical_findings)} critical/high severity issues:\n")

    for i, finding in enumerate(critical_findings, 1):
        print(f"{i}. [{finding['severity']}] {finding['title']}")
        print(f"   Resource: {finding['resource_id']}")
        print(f"   {finding['description']}")
        print()


def example_export_all_formats():
    """Example: Export scan results in all supported formats."""
    print("\n" + "=" * 60)
    print("Multi-Format Export Example")
    print("=" * 60)

    # Scan AWS
    scanner = AWSScanner(use_mock=True)
    results = scanner.scan()

    # Export in all formats
    formats = ['json', 'markdown', 'html']

    for fmt in formats:
        output = format_output(results, fmt)
        filename = f"aws_report.{fmt}"
        with open(filename, 'w') as f:
            f.write(output)
        print(f"Exported {fmt.upper()} report to: {filename}")


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("CloudAuditor CLI - Usage Examples")
    print("=" * 60)

    try:
        # Run examples
        example_aws_scan()
        example_gcp_scan()
        example_compare_providers()
        example_filter_critical_findings()
        example_export_all_formats()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
