import ipaddress
import sqlite3
import logging
from scripts.database import DB_FILE
from colorama import Fore, Style

def load_targets(*args):
    """
    Loads targets into the scan_results table from a file or directly from a subnet.
    :param args: Arguments passed to the command (file path or subnet).
    """
    if not args:
        print(f"{Fore.YELLOW}Usage: {Fore.CYAN}load targets <filepath|subnet>{Style.RESET_ALL}")
        return

    input_value = args[0]

    ips = []

    try:
        if '/' in input_value:  # Check if it's a subnet
            logging.info(f"Processing subnet: {input_value}")
            print(f"{Fore.CYAN}Processing subnet: {Style.BRIGHT}{input_value}{Style.RESET_ALL}")
            network = ipaddress.ip_network(input_value, strict=False)
            ips = [(str(ip),) for ip in network.hosts()]  # Skip network and broadcast addresses
        else:  # Assume it's a file
            logging.info(f"Processing file: {input_value}")
            print(f"{Fore.CYAN}Processing file: {Style.BRIGHT}{input_value}{Style.RESET_ALL}")
            with open(input_value, 'r') as file:
                lines = file.readlines()

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                try:
                    if '/' in line:  # Subnet in file
                        network = ipaddress.ip_network(line, strict=False)
                        ips.extend([(str(ip),) for ip in network.hosts()])
                    else:  # Single IP in file
                        ip = ipaddress.ip_address(line)
                        ips.append((str(ip),))
                except ValueError as ve:
                    logging.error(f"Invalid IP or subnet format: {line}. Error: {ve}")
                    print(f"{Fore.RED}Invalid IP or subnet format: {Style.BRIGHT}{line}{Style.RESET_ALL}")
                    continue

        if not ips:
            print(f"{Fore.RED}No valid IPs found in {Style.BRIGHT}{input_value}{Style.RESET_ALL}")
            return

        # Insert IPs into the database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.executemany('''
            INSERT OR IGNORE INTO scan_results (
                ip_address, protocol, port, name, cve, synopsis, plugin_output
            ) VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL)
        ''', ips)

        conn.commit()
        logging.info(f"Loaded {len(ips)} IPs into the database.")
        print(f"{Fore.GREEN}Successfully loaded {len(ips)} IPs into the database.{Style.RESET_ALL}")

    except FileNotFoundError:
        logging.error(f"File not found: {input_value}")
        print(f"{Fore.RED}File not found: {Style.BRIGHT}{input_value}{Style.RESET_ALL}")
    except ValueError as ve:
        logging.error(f"Invalid subnet format: {input_value}. Error: {ve}")
        print(f"{Fore.RED}Invalid subnet format: {Style.BRIGHT}{input_value}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error loading targets: {e}")
        print(f"{Fore.RED}Error loading targets: {Style.BRIGHT}{e}{Style.RESET_ALL}")
    finally:
        if 'conn' in locals():
            conn.close()
