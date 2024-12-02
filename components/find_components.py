import sqlite3
import dns.resolver
from scripts.database import DB_FILE, save_query_results
import logging
from colorama import Fore, Style

# Mapping of AD components and their DNS query prefixes
INFRASTRUCTURE = {
    "Domain Controllers": "_ldap._tcp.dc._msdcs.",
    "Global Catalog Servers": "_gc._tcp.",
    "Kerberos Servers": "_kerberos._tcp.dc._msdcs.",
    "KDC Servers": "_kerberos._tcp.kdc._msdcs.",
    "SQL Servers": "_mssql._tcp.",
    "Certificate Authorities": "_vlmcs._tcp.",
    "Management Point (SCCM)": "_mps._tcp.",
    "AD Lightweight Directory Services": "_ldap._tcp.",
    "AD Rights Management Services": "_rms._tcp.",
    "Web Server (IIS)": "_http._tcp.",
    "Windows Server Update Services": "_wsus._tcp.",
    "File Replication Service (FRS)": "_ldap._tcp.pdc._msdcs.",
    "File and Storage Services": "_file._tcp.",
    "Host Guardian Service": "_hgs._tcp.",
    "Hyper-V": "_hyperv._tcp.",
    "Print and Document Services": "_print._tcp.",
    "Remote Access": "_remote._tcp.",
    "PDC Emulator (FRS)": "_ldap._tcp.pdc._msdcs.",
    "Remote Desktop Services": "_rdp._tcp.",
    "Volume Activation Services": "_vlmcs._tcp.",
    "Device Health Attestation": "_dha._tcp.",
    "DHCP Servers": "_dhcp._udp.",
    "Time Servers": "_ntp._udp.",
    "Backup Domain Controllers": "_ldap._tcp.bdc._msdcs.",
    "Federation Servers (AD FS)": "_ldap._tcp.adfs._msdcs.",
    "Cluster Services": "_ldap._tcp.clusters._msdcs.",
    "Network Policy Server (NPS)": "_radius._udp.",
    "DFS Namespace Servers": "_ldap._tcp.dfs._msdcs.",
    "Certificate Enrollment Services": "_cert._tcp.",
    "Azure AD Connect": "_ldap._tcp.sync._msdcs.",
    "SMTP Relay Services": "_smtp._tcp."
}

def find_components(*args):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get DNS servers and domains from the database
    try:
        cursor.execute("SELECT ip_address FROM dns_servers")
        dns_servers = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT domain_name FROM domains")
        domains = [row[0] for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Error retrieving DNS servers or domains: {e}")
        print(f"{Fore.RED}Error retrieving DNS servers or domains. Check logs.{Style.RESET_ALL}")
        return
    finally:
        conn.close()

    if not dns_servers or not domains:
        logging.info("No DNS servers or domains found in the database.")
        print(f"{Fore.RED}No DNS servers or domains found in the database.{Style.RESET_ALL}")
        return

    logging.info("Querying components...")
    detected_components = []

    for domain in domains:
        print(f"{Fore.CYAN}{'-'*40}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}Querying components for domain: {domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

        for component_name, prefix in INFRASTRUCTURE.items():
            query = f"{prefix}{domain}"
            logging.debug(f"Querying {component_name}: {query}")

            for dns_server in dns_servers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]

                    # Perform SRV query
                    answers = resolver.resolve(query, "SRV")
                    for srv in answers:
                        target = str(srv.target).rstrip('.')
                        logging.debug(f"Found SRV record: {target} for {component_name}")

                        # Perform A query to get the IP address of the target
                        ip_answers = resolver.resolve(target, "A")
                        for ip in ip_answers:
                            ip_address = ip.to_text()
                            logging.debug(f"Resolved {target} to {ip_address}")
                            detected_components.append((component_name, target, ip_address))

                except dns.resolver.NoAnswer:
                    logging.debug(f"No answer for {query} on {dns_server}")
                except dns.resolver.NXDOMAIN:
                    logging.debug(f"Query {query} does not exist on {dns_server}")
                except Exception as e:
                    logging.error(f"Error querying {query} on {dns_server}: {e}")

    # Insert detected components into the database
    if detected_components:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            for component, hostname, ip_address in detected_components:
                cursor.execute('''
                    INSERT OR IGNORE INTO components (component, hostname, ip_address)
                    VALUES (?, ?, ?)
                ''', (component, hostname, ip_address))
            conn.commit()
            logging.info("Detected components saved to the database.")
        except Exception as e:
            logging.error(f"Error saving components to the database: {e}")
        finally:
            conn.close()

        # Output results
        print(f"{Style.BRIGHT}{Fore.YELLOW}Components Detected:{Style.RESET_ALL}")
        for component, hostname, ip_address in detected_components:
            print(f"{Style.BRIGHT}{Fore.YELLOW}{component}:{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}{hostname} ({ip_address}){Style.RESET_ALL}")
        save_query_results("find_components", detected_components)
    else:
        print(f"{Fore.RED}No components detected.{Style.RESET_ALL}")
