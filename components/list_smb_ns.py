import sqlite3
from scripts.database import DB_FILE, save_query_results
import logging
from colorama import Fore, Style


def list_smb_ns(*args):
    """
    Lists all hosts where SMB signing is not required.
    Also ensures hosts from Nessus results are added to the smb_ns_hosts table.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Step 1: Retrieve hosts from the scan_results table
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM scan_results
            WHERE name = "SMB Signing not required"
        ''')
        nessus_hosts = cursor.fetchall()

        # Step 2: Insert Nessus hosts into the smb_ns_hosts table
        for (ip,) in nessus_hosts:
            cursor.execute('''
                INSERT OR IGNORE INTO smb_ns_hosts (ip_address)
                VALUES (?)
            ''', (ip,))

        conn.commit()

        # Step 3: Retrieve all unique hosts from the smb_ns_hosts table
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM smb_ns_hosts
        ''')
        smb_ns_hosts = cursor.fetchall()

        # Step 4: Display results
        if smb_ns_hosts:
            print(f"{Fore.CYAN}{'-'*40}")
            print(f"{Style.BRIGHT}{Fore.YELLOW}Hosts with SMB Signing Not Required:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")
            for (ip,) in smb_ns_hosts:
                print(f"{Fore.GREEN}    {ip}{Style.RESET_ALL}")

            # Save query results
            save_query_results("list_smbns", smb_ns_hosts)
            logging.info(f"Listed {len(smb_ns_hosts)} hosts where SMB signing is not required.")
        else:
            print(f"{Fore.YELLOW}No hosts found where SMB signing is not required.{Style.RESET_ALL}")
            logging.info("No hosts found where SMB signing is not required.")
    except Exception as e:
        logging.error(f"Error listing SMB NS hosts: {e}")
        print(f"{Fore.RED}An error occurred while listing SMB NS hosts. Check logs for details.{Style.RESET_ALL}")
    finally:
        conn.close()
