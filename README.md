# Network Threat Intel tool

## Description

The Network Threat Intel tool is a Python script designed to query IP information from AbuseIPDB. It can process single IP addresses or a list of IP addresses from a text file. The results can be output to the console, saved to a CSV file, or saved to a JSON file.

## Features

- Query detailed information about an IP address from AbuseIPDB.
- Support for processing multiple IP addresses from a text file.
- Option to save results to CSV and/or JSON files.
- Handles private IP addresses gracefully by skipping them.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/H4k3R4FT3RD4Rk/network-threat-intel.git
   cd network-threat-intel
   ```

2. **Install Required Libraries**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Set Up Your AbuseIPDB API Key**
   - Obtain your API key from [AbuseIPDB](https://www.abuseipdb.com/).
   - Save the API key in a file named `api_key.txt` in the same directory as the script.

## Usage

### Single IP Query

To query a single IP address, use the `-i` or `--ip` option followed by the IP address.

```bash
python3 network_threat_intel.py -i 8.8.8.8 -d 30
```

### Query from a File

To query multiple IP addresses from a text file, use the `-f` or `--file` option followed by the file path.

```bash
python3 network_threat_intel.py -f ip_list.txt -d 30
```

### Save Output to CSV

To save the output to a CSV file, use the `-c` or `--csv` option followed by the CSV file name.

```bash
python3 network_threat_intel.py -i 8.8.8.8 -c output.csv
```

### Save Output to JSON

To save the output to a JSON file, use the `-jf` or `--json-file` option followed by the JSON file name.

```bash
python3 network_threat_intel.py -i 8.8.8.8 -jf output.json
```

### Output in JSON Format

To print the output in JSON format to the console, use the `-j` or `--json` option.

```bash
python3 network_threat_intel.py -i 8.8.8.8 -j
```

## Arguments

- `-i, --ip`: IP address to look up (e.g., `8.8.8.8`).
- `-f, --file`: Path to a `.txt` file containing a list of IP addresses.
- `-d, --days`: Number of days to look back for IP reports. Default is 90 days.
- `-j, --json`: Output in JSON format.
- `-c, --csv`: Save output to a CSV file. Provide the file name.
- `-jf, --json-file`: Save output to a JSON file. Provide the file name.

## Example Usage

```bash
python3 network_threat_intel.py -i 8.8.8.8 -d 30 -j
python3 network_threat_intel.py -f ip_list.txt -d 30 -c output.csv
```

