# nessuscrape

## About

Nessuscrape is a CLI tool built in Python that scrapes Nessus HTML reports for host information, namely IP address, DNS, and OS.  Output is in .csv format.  Useful for quickly identifying the scanned hosts contained in a report for cross-referencing multiple scans or cleaning up your Nessus schedules.  Nessus doesn't readily display a host's IP address and associated DNS name in the webUI, so this scraper can also be useful for inventory purposes.

## Usage

Run this tool via cli.  HTML files should be placed in this script's running directory.  If only one valid file is found it will parse that file.  If multiple .html Nessus reports are available in the current directory, the tool will ask which to parse.  The tool will create a folder called 'results' and place the .csv output there.