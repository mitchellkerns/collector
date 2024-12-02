import sqlite3
from impacket.smbconnection import SMBConnection
from scripts.database import DB_FILE
import logging
from colorama import Fore, Style


def find_smbns(*args):
    """
    Scans hosts with port 445 open in the database to identify SMB servers
    where signing is not required. Displays only the count of hosts found.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Retrieve all IP addresses with port 445 open
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM scan_results
            WHERE port = 445
        ''')
        hosts = [row[0] for row in cursor.fetchall()]

        if not hosts:
            print(f"{Fore.RED}No hosts with port 445 found in the database.{Style.RESET_ALL}")
            logging.info("No hosts with port 445 found in the database.")
            return

        logging.info(f"Starting SMB signing scan for {len(hosts)} hosts...")
        print(f"{Fore.CYAN}{'-'*40}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}Scanning SMB Hosts for Signing Status...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

        smb_ns_hosts = []

        for ip in hosts:
            try:
                logging.debug(f"Connecting to {ip} via SMB...")

                smb = SMBConnection(ip, ip, timeout=5)
                smb.login('', '')  # Attempt anonymous login

                signing_required = smb.isSigningRequired()
                smb.logoff()

                if not signing_required:
                    smb_ns_hosts.append((ip,))
                    logging.info(f"{ip} does not require SMB signing.")

            except Exception as e:
                logging.error(f"Error scanning {ip}: {e}")
                continue

        # Insert results into the smb_ns_hosts table
        if smb_ns_hosts:
            cursor.executemany('''
                INSERT OR IGNORE INTO smb_ns_hosts (ip_address)
                VALUES (?)
            ''', smb_ns_hosts)
            conn.commit()

            print(f"\n{Fore.GREEN}{len(smb_ns_hosts)} hosts found with SMB signing not required.{Style.RESET_ALL}")
            logging.info(f"{len(smb_ns_hosts)} hosts found with SMB signing not required.")
        else:
            print(f"{Fore.YELLOW}No hosts found with SMB signing not required.{Style.RESET_ALL}")
            logging.info("No hosts found with SMB signing not required.")

    except Exception as e:
        logging.error(f"Error during SMB signing scan: {e}")
        print(f"{Fore.RED}An error occurred during the SMB signing scan. Check logs for details.{Style.RESET_ALL}")
    finally:
        conn.close()
