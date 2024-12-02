import pandas as pd
import sqlite3
from scripts.database import DB_FILE
import logging
from colorama import Fore, Style

def load_nessuscsv(filepath, *args):  # Accepts filepath and additional arguments
    try:
        print(f"{Fore.CYAN}{'-'*40}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}Loading Nessus CSV File...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

        # Read the Nessus CSV file
        df = pd.read_csv(filepath)
        results = []

        for _, row in df.iterrows():
            cve = row.get("CVE", "")
            ip = row.get("Host")
            protocol = row.get("Protocol")
            port = row.get("Port")
            name = row.get("Name")
            synopsis = row.get("Synopsis", "")
            plugin_output = row.get("Plugin Output", "")

            if not ip or not protocol or not port or not name:
                continue

            results.append((cve, ip, protocol, int(port), name, synopsis, plugin_output))

        # Insert results into the database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.executemany('''
            INSERT OR IGNORE INTO scan_results (
                cve, ip_address, protocol, port, name, synopsis, plugin_output
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', results)

        conn.commit()
        conn.close()

        logging.info(f"Loaded {len(results)} entries from {filepath} into the database.")
        print(f"{Style.BRIGHT}{Fore.GREEN}Successfully loaded {len(results)} entries from {filepath} into the database.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error loading Nessus CSV: {e}")
        print(f"{Style.BRIGHT}{Fore.RED}Error loading Nessus CSV: {e}{Style.RESET_ALL}")
