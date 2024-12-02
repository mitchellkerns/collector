import sqlite3
from components.find_domains import find_domains
from scripts.database import DB_FILE, save_query_results
import logging
from colorama import Fore, Style

def list_domains(*args):
    """
    Lists domains stored in the database. If no domains are found, prompts the user to run the `find_domains` command.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Query the database for domains
        cursor.execute('''
            SELECT DISTINCT domain_name
            FROM domains
        ''')
        domains = [row[0] for row in cursor.fetchall()]

        if domains:
            print(f"{Style.BRIGHT}{Fore.CYAN}Domains in the database:{Style.RESET_ALL}")
            for domain in domains:
                print(f"{Fore.YELLOW}{domain}{Style.RESET_ALL}")

            # Save query results for auditing or later use
            save_query_results("list_domains", domains)
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}No domains found in the database.{Style.RESET_ALL}")
            user_input = input(f"{Fore.CYAN}Would you like to find domains now? (yes/no): {Style.RESET_ALL}").strip().lower()
            if user_input in ['yes', 'y']:
                find_domains()
            else:
                print(f"{Style.BRIGHT}{Fore.RED}No domains listed.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error retrieving domains from the database: {e}")
        print(f"{Fore.RED}An error occurred while retrieving domains. Check the logs for details.{Style.RESET_ALL}")
    finally:
        conn.close()
