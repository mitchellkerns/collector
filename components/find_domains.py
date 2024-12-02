import socket
from impacket.smbconnection import SMBConnection
import sqlite3
from scripts.database import DB_FILE, save_query_results
import logging
from colorama import Fore, Style

# User-configurable domain suffixes
DEFAULT_DOMAIN_SUFFIXES = ['.local', '.com', '.net', '.org']

def find_domains(*args):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM scan_results
            WHERE port = 445 AND name = "Microsoft Windows SMB Service Detection"
        ''')
        hosts = cursor.fetchall()
    except Exception as e:
        logging.error(f"Error retrieving hosts for SMB scan: {e}")
        print(f"{Fore.RED}Error retrieving hosts for SMB scan. Check logs for details.{Style.RESET_ALL}")
        return
    finally:
        conn.close()

    if not hosts:
        logging.info("No hosts with SMB detected.")
        print(f"{Fore.RED}No domains detected.{Style.RESET_ALL}")
        return

    logging.info("Initiating SMB scans...")
    print(f"{Fore.CYAN}{'-'*40}")
    print(f"{Style.BRIGHT}{Fore.YELLOW}Initiating SMB Scans...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

    detected_domains = set()

    for (ip,) in hosts:
        try:
            logging.debug(f"Scanning {ip} using SMB...")
            smb = SMBConnection(ip, ip, timeout=5)
            smb.login('', '')  # Anonymous login

            domain_name = smb.getServerDomain().lower()
            fqdn = smb.getServerName().lower()

            logging.debug(f"SMB details for {ip}: Domain='{domain_name}', FQDN='{fqdn}'")

            # Validate and infer domain name
            if domain_name and '.' in domain_name:
                detected_domains.add(domain_name)
                logging.debug(f"Valid domain detected: {domain_name}")
            elif domain_name:
                for suffix in DEFAULT_DOMAIN_SUFFIXES:
                    inferred_domain = f"{domain_name}{suffix}"
                    detected_domains.add(inferred_domain)
                    logging.debug(f"Inferred domain: {inferred_domain}")
                    break

            smb.logoff()
        except Exception as e:
            logging.error(f"SMB query failed for {ip}: {e}")
            # Only log errors without printing them to the screen
            continue

    # Insert only unique domains into the database
    if detected_domains:
        print(f"{Style.BRIGHT}{Fore.YELLOW}Domains Detected:{Style.RESET_ALL}")
        for domain in detected_domains:
            print(f"    {Fore.GREEN}{domain}{Style.RESET_ALL}")

        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            for domain in detected_domains:
                # Store only valid domains
                if '.' in domain and not domain.split('.')[0].isdigit():
                    cursor.execute('''
                        INSERT OR IGNORE INTO domains (domain_name)
                        VALUES (?)
                    ''', (domain,))
            conn.commit()
            logging.info("Detected domains saved to the database.")
        except Exception as e:
            logging.error(f"Error saving detected domains: {e}")
            print(f"{Fore.RED}Error saving detected domains. Check logs for details.{Style.RESET_ALL}")
        finally:
            conn.close()

        save_query_results("find_domains", list(detected_domains))
    else:
        print(f"{Fore.RED}No domains detected.{Style.RESET_ALL}")
