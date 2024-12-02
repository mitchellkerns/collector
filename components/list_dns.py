import sqlite3
import logging
from scripts.database import DB_FILE, save_query_results
from colorama import Fore, Style

def list_dns(*args):
    """
    Lists DNS servers stored in the database. If none exist, informs the user and saves results.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Query unique IPs where name is exactly "DNS Server Detection"
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM scan_results
            WHERE name = "DNS Server Detection"
        ''')
        dns_servers = cursor.fetchall()

        if dns_servers:
            print(f"{Style.BRIGHT}{Fore.CYAN}DNS Servers Detected:{Style.RESET_ALL}")
            for (ip,) in dns_servers:
                print(f"{Fore.YELLOW}{ip}{Style.RESET_ALL}")
                # Insert unique DNS servers into the database
                cursor.execute('''
                    INSERT OR IGNORE INTO dns_servers (ip_address)
                    VALUES (?)
                ''', (ip,))
            conn.commit()
            logging.info("Detected DNS servers saved to the database.")
        else:
            print(f"{Style.BRIGHT}{Fore.YELLOW}No DNS servers found.{Style.RESET_ALL}")

        # Save query results to the query_results table
        save_query_results("list_dns", dns_servers)

    except Exception as e:
        logging.error(f"Error retrieving DNS servers: {e}")
        print(f"{Fore.RED}An error occurred while retrieving DNS servers: {e}{Style.RESET_ALL}")
    finally:
        conn.close()
