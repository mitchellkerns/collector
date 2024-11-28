from impacket.smbconnection import SMBConnection
import sqlite3
from scripts.database import DB_FILE, save_query_results

def find_domains():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Get all unique hosts with port 445 open and the specified "Name"
        cursor.execute('''
            SELECT DISTINCT ip_address
            FROM scan_results
            WHERE port = 445 AND name = "Microsoft Windows SMB Service Detection"
        ''')
        hosts = cursor.fetchall()
    except Exception as e:
        print(f"Error retrieving hosts for SMB scan: {e}")
        return
    finally:
        conn.close()

    if not hosts:
        print("No hosts with SMB detected.")
        return

    print("Initiating SMB scans...")
    unique_domains = set()

    for (ip,) in hosts:
        try:
            # Establish an SMB connection to the host
            smb = SMBConnection(ip, ip, timeout=5)
            smb.login('', '')  # Attempt anonymous login
            
            # Retrieve the domain name from the SMB connection
            server_domain = smb.getServerDomain()
            if server_domain:
                unique_domains.add(server_domain)
            
            smb.logoff()
        except Exception as e:
            print(f"Error scanning host {ip}: {e}")
            continue

    if unique_domains:
        print("Domains Detected:")
        for domain in unique_domains:
            print(domain)
    else:
        print("No domains detected.")

    # Save results to the database
    save_query_results("find_domains", list(unique_domains))
