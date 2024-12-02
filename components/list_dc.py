import sqlite3
from scripts.database import DB_FILE, save_query_results
from components.find_dc import find_dc
from components.find_domains import find_domains
import logging
from colorama import Fore, Style


def list_dc(*args):
    """
    Lists domain controllers stored in the database. If none exist, prompts the user to find domains and domain controllers.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Check if any domains exist in the database
        cursor.execute('SELECT DISTINCT domain_name FROM domains')
        domain_results = cursor.fetchall()

        if not domain_results:
            print(f"{Style.BRIGHT}{Fore.YELLOW}No domains found in the database.{Style.RESET_ALL}")
            response = input("Would you like to find domains now? (yes/no): ").strip().lower()
            if response == "yes":
                find_domains()
            else:
                print(f"{Fore.RED}Cannot list domain controllers without domains. Exiting.{Style.RESET_ALL}")
                return

        # Query the database for domain controllers
        cursor.execute('SELECT DISTINCT hostname, ip_address FROM domain_controllers')
        dc_results = cursor.fetchall()

        if dc_results:
            print(f"{Style.BRIGHT}{Fore.CYAN}Domain Controllers in the database:{Style.RESET_ALL}")
            for hostname, ip in dc_results:
                print(f"{Fore.GREEN}{hostname}{Style.RESET_ALL} ({Fore.YELLOW}{ip}{Style.RESET_ALL})")

            # Save query results
            save_query_results("list_dc", dc_results)
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}No domain controllers found in the database.{Style.RESET_ALL}")
            response = input("Would you like to find domain controllers now? (yes/no): ").strip().lower()
            if response == "yes":
                find_dc()
            else:
                print(f"{Fore.RED}No domain controllers listed.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error listing domain controllers: {e}")
        print(f"{Fore.RED}An error occurred while listing domain controllers: {e}{Style.RESET_ALL}")
    finally:
        conn.close()
