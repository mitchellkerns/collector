import sqlite3
from scripts.database import DB_FILE, save_query_results

def list_dns():
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
    except Exception as e:
        print(f"Error retrieving DNS servers: {e}")
        return
    finally:
        conn.close()

    if dns_servers:
        print("DNS Servers:")
        for (ip,) in dns_servers:
            print(ip)
    else:
        print("No DNS servers found.")

    # Save query results to the database
    save_query_results("list_dns", dns_servers)
