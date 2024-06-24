import os
import csv
import json
import argparse
import requests
import ipaddress
from datetime import datetime

API_KEY_FILE = 'api_key.txt'

# HEADER
def print_header():
    header = """
 Developed by:
  _    _ _  _   _    ____  _____  _  _   ______ _______ ____  _____  _____  _  _   _____  _  __
 | |  | | || | | |  |___ \|  __ \| || | |  ____|__   __|___ \|  __ \|  __ \| || | |  __ \| |/ /
 | |__| | || |_| | __ __) | |__) | || |_| |__     | |    __) | |__) | |  | | || |_| |__) | ' / 
  |  __  |__   _| |/ /|__ <|  _  /|__   _|  __|    | |   |__ <|  _  /| |  | |__   _|  _  /|  <  
 | |  | |  | | |   < ___) | | \ \   | | | |       | |   ___) | | \ \| |__| |  | | | | \ \| . \ 
 |_|  |_|  |_| |_|\_\____/|_|  \_\  |_| |_|       |_|  |____/|_|  \_\_____/   |_| |_|  \_\_|\_\\
                                                                                               
    """
    print(header)
    print("=" * 100)
    print("A tool to query IP information from AbuseIPDB".center(100, " "))
    print(f"Run Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(100, " "))
    print("=" * 100)

# Load API key from file or prompt user
def get_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, 'r') as file:
            api_key = file.read().strip()
        if api_key:
            return api_key

    api_key = input('API Key not found.\nEnter your API Key for AbuseIPDB: ')
    with open(API_KEY_FILE, 'w') as file:
        file.write(api_key)
    return api_key

api_key = get_api_key()

def check_ip_abuse(ip, days, api_key):
    if ipaddress.ip_address(ip).is_private:
        return {"message": f"{ip} is a private IP. No results."}

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': days,
        'verbose': ''
    }
    response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
    return response.json()

def save_to_csv(ip_data, csv_file):
    if 'data' in ip_data:
        data = ip_data['data']
        if isinstance(data, dict):
            data = [data]
        keys = data[0].keys()
        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for entry in data:
                writer.writerow(entry)
        print(f"Data saved to {csv_file}")
    else:
        print("No data found.")

def save_to_json(ip_data, json_file):
    with open(json_file, 'w') as file:
        json.dump(ip_data, file, indent=4)
    print(f"Data saved to {json_file}")

def format_reports(reports):
    formatted_reports = []
    for report in reports:
        report_str = (
            f"Reported At: {report['reportedAt']}\n"
            f"Comment: {report['comment']}\n"
            f"Categories: {', '.join(map(str, report['categories']))}\n"
            f"Reporter ID: {report['reporterId']}\n"
            f"Reporter Country Code: {report['reporterCountryCode']}\n"
            f"Reporter Country Name: {report['reporterCountryName']}\n"
            "----------------------------------"
        )
        formatted_reports.append(report_str)
    return "\n".join(formatted_reports)

def process_ip(ip, days, api_key, json_output, csv_file, json_file):
    result = check_ip_abuse(ip, days, api_key)
    if csv_file:
        save_to_csv(result, csv_file)
    if json_file:
        save_to_json(result, json_file)
    else:
        if 'data' in result:
            ip_data = result['data']
            if json_output:
                print(json.dumps(ip_data, indent=4))
            else:
                print(f"Results for IP {ip}:")
                print(f"IP Address: {ip_data['ipAddress']}")
                print(f"Is Public: {ip_data['isPublic']}")
                print(f"IP Version: {ip_data['ipVersion']}")
                print(f"Is Whitelisted: {ip_data['isWhitelisted']}")
                print(f"Abuse Confidence Score: {ip_data['abuseConfidenceScore']}")
                print(f"Country Code: {ip_data['countryCode']}")
                print(f"Usage Type: {ip_data['usageType']}")
                print(f"ISP: {ip_data['isp']}")
                print(f"Domain: {ip_data['domain']}")
                print(f"Hostnames: {', '.join(ip_data['hostnames'])}")
                print(f"Is Tor: {ip_data['isTor']}")
                print(f"Country Name: {ip_data['countryName']}")
                print(f"Total Reports: {ip_data['totalReports']}")
                print(f"Number of Distinct Users: {ip_data['numDistinctUsers']}")
                print(f"Last Reported At: {ip_data['lastReportedAt']}")
                print("\nReports:")
                print(format_reports(ip_data['reports']))
        else:
            print(f"No data found for IP {ip}.")

def main():
    parser = argparse.ArgumentParser(
        description='Query AbuseIPDB for IP address information.',
        epilog=(
            'Example usage: python script.py -i 8.8.8.8 -d 30 -j\n'
            'Note: To change the API key, find the api_key.txt file in the script directory and edit its content.'
        )
    )
    parser.add_argument(
        '-i', '--ip', help='IP address to look up. Example: 8.8.8.8'
    )
    parser.add_argument(
        '-f', '--file', help='Path to a .txt file containing a list of IP addresses to look up.'
    )
    parser.add_argument(
        '-d', '--days', type=int, default=90, help='Number of days to look back for IP reports. Default: 90 days'
    )
    parser.add_argument(
        '-j', '--json', action='store_true', help='Output in JSON format'
    )
    parser.add_argument(
        '-c', '--csv', help='Save output to a CSV file. Provide the file name.'
    )
    parser.add_argument(
        '-jf', '--json-file', help='Save output to a JSON file. Provide the file name.'
    )

    args = parser.parse_args()

    print_header()

    if args.file:
        if os.path.exists(args.file):
            with open(args.file, 'r') as file:
                ips = file.readlines()
            ips = [ip.strip() for ip in ips]
            for ip in ips:
                process_ip(ip, args.days, api_key, args.json, args.csv, args.json_file)
        else:
            print(f"File {args.file} not found.")
    elif args.ip:
        process_ip(args.ip, args.days, api_key, args.json, args.csv, args.json_file)
    else:
        print("Please provide an IP address or a file containing IP addresses using -i or -f option.")

if __name__ == '__main__':
    main()
