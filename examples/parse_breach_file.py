#!/usr/bin/env python3
"""
Example: Parse stealer logs and generate reports.

Demonstrates parsing various infostealer log formats
and generating output in multiple formats.

Author: Cameron Hopkin
License: MIT
"""
import sys
import tempfile
from pathlib import Path

# Add parent directory to path for local development
sys.path.insert(0, str(__file__).rsplit('/', 2)[0] + '/src')

from breach_toolkit.parsers.stealer_log_parser import StealerLogParser
from breach_toolkit.parsers.combo_parser import ComboParser
from breach_toolkit.reporters.json_reporter import JSONReporter
from breach_toolkit.reporters.csv_reporter import CSVReporter
from breach_toolkit.reporters.html_reporter import HTMLReporter


def create_sample_files() -> dict[str, str]:
    """Create sample log files for demonstration."""
    samples = {}

    # Redline format sample
    redline_content = """URL: https://mail.google.com/login
Username: john.doe@gmail.com
Password: SecretPass123
Application: Chrome

URL: https://facebook.com/login
Username: johndoe
Password: FBPassword456
Application: Firefox

URL: https://twitter.com/login
Username: @johndoe
Password: Tw1tt3rP@ss
Application: Edge
"""

    # Combo list sample
    combo_content = """user1@example.com:password123
admin@company.com:AdminP@ss!
test.user@domain.org:TestSecret99
info@website.net:InfoPass456
"""

    # Create temp files
    with tempfile.NamedTemporaryFile(mode='w', suffix='_redline.txt', delete=False) as f:
        f.write(redline_content)
        samples['redline'] = f.name

    with tempfile.NamedTemporaryFile(mode='w', suffix='_combo.txt', delete=False) as f:
        f.write(combo_content)
        samples['combo'] = f.name

    return samples


def parse_stealer_logs(filepath: str):
    """Parse stealer log file."""
    print(f"\n{'='*50}")
    print("Parsing Stealer Logs")
    print('='*50)

    parser = StealerLogParser(deduplicate=True)
    credentials = list(parser.parse_file(filepath))

    print(f"Parsed {len(credentials)} credentials:")
    for cred in credentials:
        print(f"  • {cred.domain}")
        print(f"    User: {cred.username}")
        print(f"    Pass: {'*' * len(cred.password)}")
        print(f"    Type: {cred.stealer_type}")
        print()

    return credentials


def parse_combo_list(filepath: str):
    """Parse combo list file."""
    print(f"\n{'='*50}")
    print("Parsing Combo List")
    print('='*50)

    parser = ComboParser(validate_emails=True)
    entries = list(parser.parse_file(filepath))

    print(f"Parsed {len(entries)} entries:")
    for entry in entries:
        print(f"  • {entry.email}")
        print(f"    Domain: {entry.domain}")
        print(f"    Pass: {'*' * len(entry.password)}")
        print()

    stats = parser.get_stats()
    print(f"Stats: {stats}")

    return entries


def generate_reports(credentials, output_dir: str = "."):
    """Generate reports in multiple formats."""
    print(f"\n{'='*50}")
    print("Generating Reports")
    print('='*50)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # JSON report
    json_reporter = JSONReporter(mask_passwords=True)
    json_file = output_path / "breach_report.json"
    json_reporter.save(credentials, str(json_file), title="Breach Analysis Report")
    print(f"✅ JSON report: {json_file}")

    # CSV report
    csv_reporter = CSVReporter(mask_passwords=True)
    csv_file = output_path / "breach_report.csv"
    csv_reporter.save(credentials, str(csv_file))
    print(f"✅ CSV report: {csv_file}")

    # HTML report
    html_reporter = HTMLReporter(title="Breach Analysis Report", mask_passwords=True)
    html_file = output_path / "breach_report.html"
    html_reporter.save(credentials, str(html_file))
    print(f"✅ HTML report: {html_file}")

    # Summary report
    summary = json_reporter.generate_summary(credentials)
    summary_file = output_path / "breach_summary.json"
    with open(summary_file, 'w') as f:
        f.write(summary)
    print(f"✅ Summary report: {summary_file}")


def cleanup_files(files: dict[str, str]):
    """Clean up temporary files."""
    for filepath in files.values():
        Path(filepath).unlink(missing_ok=True)


def main():
    """Main entry point."""
    print("=" * 50)
    print("Breach Toolkit - Parse & Report Example")
    print("=" * 50)

    # Check for command line argument
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if Path(filepath).exists():
            print(f"Parsing file: {filepath}")
            credentials = parse_stealer_logs(filepath)
            generate_reports(credentials)
            return

    # Create sample files for demonstration
    print("\nNo input file provided. Creating sample files for demonstration...")
    samples = create_sample_files()

    try:
        # Parse stealer logs
        credentials = parse_stealer_logs(samples['redline'])

        # Parse combo list
        combo_entries = parse_combo_list(samples['combo'])

        # Generate reports from stealer logs
        with tempfile.TemporaryDirectory() as tmpdir:
            generate_reports(credentials, tmpdir)
            print(f"\nReports generated in: {tmpdir}")

            # Show sample of HTML report
            html_content = Path(tmpdir) / "breach_report.html"
            if html_content.exists():
                print(f"\nHTML report preview (first 500 chars):")
                print("-" * 40)
                print(html_content.read_text()[:500])
                print("...")

    finally:
        # Clean up
        cleanup_files(samples)
        print("\n✅ Cleaned up sample files")


if __name__ == "__main__":
    main()
