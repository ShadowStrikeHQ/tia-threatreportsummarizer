# tia-ThreatReportSummarizer
A command-line tool that takes a URL or local path to a threat intelligence report (e.g., a PDF or text file) and generates a concise summary highlighting key IOCs, MITRE ATT&CK techniques, and affected systems. Uses NLP techniques like sentence extraction and keyword analysis. - Focused on Aggregates and normalizes threat intelligence feeds from various open-source sources (e.g., threat lists, vulnerability databases, malware signatures) into a structured format for consumption by other security tools.  Focuses on automating the collection, parsing, and standardization of data.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-threatreportsummarizer`

## Usage
`./tia-threatreportsummarizer [params]`

## Parameters
- `-h`: Show help message and exit
- `--output`: Path to save the summary. If not provided, prints to standard output.
- `--format`: No description provided

## License
Copyright (c) ShadowStrikeHQ
