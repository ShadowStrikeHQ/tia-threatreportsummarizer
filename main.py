import argparse
import logging
import os
import sys
import requests
from bs4 import BeautifulSoup
import re
import json  # For structured data output if needed


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="tia-ThreatReportSummarizer: Summarizes threat intelligence reports.")
    parser.add_argument("source", help="URL or local path to the threat intelligence report.")
    parser.add_argument(
        "--output",
        "-o",
        help="Path to save the summary. If not provided, prints to standard output.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output format: text (default) or json.",
    )  # Adding format argument

    return parser.parse_args()


def download_report(url):
    """
    Downloads the report from the given URL.

    Args:
        url (str): The URL to download the report from.

    Returns:
        str: The content of the report as text, or None if an error occurred.
    """
    try:
        response = requests.get(url, stream=True)  # Added stream=True for large files
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Check content type to handle HTML
        content_type = response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            soup = BeautifulSoup(response.text, "html.parser")
            text = soup.get_text(separator="\n", strip=True)  # Extract text from HTML
            return text
        elif "application/pdf" in content_type:
             logging.warning("PDF files are not yet supported. Please use a text-based report.")
             return None  #Or implement PDF parsing if possible

        return response.text

    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading report from {url}: {e}")
        return None


def read_report_from_file(filepath):
    """
    Reads the report from the given file path.

    Args:
        filepath (str): The path to the report file.

    Returns:
        str: The content of the report as text, or None if an error occurred.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None


def extract_iocs(report_text):
    """
    Extracts potential IOCs from the report text.
    This is a VERY basic implementation and should be improved with better regex and IOC type detection.

    Args:
        report_text (str): The text of the report.

    Returns:
        list: A list of potential IOCs.
    """
    # Simple regex for IPs, domains, and hashes (improve as needed)
    ip_regex = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    domain_regex = r"\b(?:[A-Za-z0-9-]+(?:\.[A-Za-z]{2,}))+\b"  # Basic domain regex
    hash_regex = r"\b[a-f0-9]{32,128}\b"  # Basic hash regex (MD5, SHA1, SHA256, SHA512)

    ips = re.findall(ip_regex, report_text)
    domains = re.findall(domain_regex, report_text)
    hashes = re.findall(hash_regex, report_text)

    return {"ips": list(set(ips)), "domains": list(set(domains)), "hashes": list(set(hashes))}


def extract_mitre_techniques(report_text):
    """
    Extracts MITRE ATT&CK techniques from the report text.
    This is a VERY basic implementation and should be improved with a MITRE ATT&CK knowledge base.

    Args:
        report_text (str): The text of the report.

    Returns:
        list: A list of potential MITRE ATT&CK techniques.
    """
    # Basic regex for MITRE ATT&CK technique IDs (e.g., T1059.001)
    mitre_regex = r"T[0-9]{4}(?:\.[0-9]{3})?"
    techniques = re.findall(mitre_regex, report_text)
    return list(set(techniques))


def summarize_report(report_text):
    """
    Summarizes the report text by extracting key IOCs and MITRE ATT&CK techniques.
    This is a basic summary function and can be improved with NLP techniques.

    Args:
        report_text (str): The text of the report.

    Returns:
        dict: A dictionary containing the summary information.
    """
    iocs = extract_iocs(report_text)
    mitre_techniques = extract_mitre_techniques(report_text)

    summary = {
        "iocs": iocs,
        "mitre_techniques": mitre_techniques,
    }

    return summary


def save_summary(summary, output_path, output_format):
    """
    Saves the summary to the specified output path in the specified format.

    Args:
        summary (dict): The summary data.
        output_path (str): The path to save the summary to.
        output_format (str): The format to save the summary in (text or json).
    """
    try:
        if output_format == "text":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("Threat Intelligence Report Summary\n")
                f.write("-----------------------------------\n")
                f.write("\nIOCs:\n")
                f.write(f"  IP Addresses: {', '.join(summary['iocs']['ips']) or 'None'}\n")
                f.write(f"  Domains: {', '.join(summary['iocs']['domains']) or 'None'}\n")
                f.write(f"  Hashes: {', '.join(summary['iocs']['hashes']) or 'None'}\n")
                f.write("\nMITRE ATT&CK Techniques:\n")
                f.write(f"  {', '.join(summary['mitre_techniques']) or 'None'}\n")
        elif output_format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=4)

        logging.info(f"Summary saved to: {output_path} in {output_format} format.")
    except IOError as e:
        logging.error(f"Error saving summary to {output_path}: {e}")


def print_summary(summary, output_format):
    """
    Prints the summary to standard output in the specified format.

    Args:
        summary (dict): The summary data.
        output_format (str): The format to print the summary in (text or json).
    """
    if output_format == "text":
        print("Threat Intelligence Report Summary")
        print("-----------------------------------")
        print("\nIOCs:")
        print(f"  IP Addresses: {', '.join(summary['iocs']['ips']) or 'None'}")
        print(f"  Domains: {', '.join(summary['iocs']['domains']) or 'None'}")
        print(f"  Hashes: {', '.join(summary['iocs']['hashes']) or 'None'}")
        print("\nMITRE ATT&CK Techniques:")
        print(f"  {', '.join(summary['mitre_techniques']) or 'None'}")
    elif output_format == "json":
        print(json.dumps(summary, indent=4))


def validate_input(source):
    """
    Validates the input source (URL or file path).

    Args:
        source (str): The input source.

    Returns:
        bool: True if the input is valid, False otherwise.
    """
    if source.startswith("http://") or source.startswith("https://"):
        return True  # Assume valid URL format
    elif os.path.isfile(source):
        return True
    else:
        logging.error("Invalid input source.  Must be a URL or a valid file path.")
        return False


def main():
    """
    Main function to orchestrate the threat report summarization process.
    """
    args = setup_argparse()
    source = args.source
    output_path = args.output
    output_format = args.format

    if not validate_input(source):
        sys.exit(1)

    report_text = None
    if source.startswith("http://") or source.startswith("https://"):
        report_text = download_report(source)
    else:
        report_text = read_report_from_file(source)

    if not report_text:
        sys.exit(1)

    summary = summarize_report(report_text)

    if output_path:
        save_summary(summary, output_path, output_format)
    else:
        print_summary(summary, output_format)


if __name__ == "__main__":
    main()