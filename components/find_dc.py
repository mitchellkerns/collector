import logging
import sqlite3
import dns.resolver
from scripts.database import DB_FILE, save_query_results
from colorama import Fore, Style


def find_dc(*args):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Retrieve all active directory domains from the database
        cursor.execute('''
            SELECT DISTINCT domain_name
            FROM domains
        ''')
        domains = cursor.fetchall()

        if not domains:
            print(f"{Fore.RED}No Active Directory domains found. Run 'find domains' first.{Style.RESET_ALL}")
            return

        # Retrieve DNS servers from the database
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM dns_servers
        ''')
        dns_servers = cursor.fetchall()

        if not dns_servers:
            print(f"{Fore.RED}No DNS servers found. Run 'list dns' first.{Style.RESET_ALL}")
            return

        logging.info("Starting DNS queries for domain controllers...")
        domain_controllers = []

        print(f"{Fore.CYAN}{'-'*40}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}Querying Domain Controllers...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

        for (domain,) in domains:
            print(f"{Fore.YELLOW}Querying domain controllers for domain: {Fore.GREEN}{domain}{Style.RESET_ALL}")
            for (dns_server,) in dns_servers:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]

                try:
                    # Perform DNS query for domain controllers
                    query = f"_ldap._tcp.dc._msdcs.{domain}"
                    answers = resolver.resolve(query, 'SRV')

                    for answer in answers:
                        hostname = str(answer.target).rstrip('.')
                        # Resolve hostname to IP address
                        ip_addresses = resolver.resolve(hostname, 'A')
                        for ip in ip_addresses:
                            domain_controllers.append((hostname, ip.to_text()))
                            print(f"    {Fore.YELLOW}Found DC:{Style.RESET_ALL} {Fore.GREEN}{hostname}{Style.RESET_ALL} ({Fore.CYAN}{ip.to_text()}{Style.RESET_ALL})")

                except Exception as e:
                    logging.error(f"Failed to query {query} on DNS server {dns_server}: {e}")
                    continue

        if domain_controllers:
            # Save results to the database
            cursor.executemany('''
                INSERT OR IGNORE INTO domain_controllers (hostname, ip_address)
                VALUES (?, ?)
            ''', domain_controllers)
            conn.commit()
            logging.info("Detected domain controllers saved to the database.")
        else:
            print(f"{Fore.RED}No domain controllers found.{Style.RESET_ALL}")
            logging.info("No domain controllers detected.")
    except Exception as e:
        logging.error(f"Error finding domain controllers: {e}")
        print(f"{Fore.RED}An error occurred while finding domain controllers. Check logs for details.{Style.RESET_ALL}")
    finally:
        conn.close()

    # Save query results for "find dc"
    save_query_results("find_dc", domain_controllers)
