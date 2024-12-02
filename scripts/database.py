import sqlite3
import os
import json

DB_FILE = os.path.join(os.getcwd(), "ad_enum.db")

def initialize_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create the scan_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT,
            ip_address TEXT,
            protocol TEXT,
            port INTEGER,
            name TEXT,
            synopsis TEXT,
            plugin_output TEXT,
            UNIQUE(ip_address, name, port, protocol) ON CONFLICT IGNORE
        )
    ''')

    # Create the domains table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_name TEXT UNIQUE
        )
    ''')

    # Create the dns_servers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE
        )
    ''')

    # Create the domain_controllers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_controllers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            ip_address TEXT,
            UNIQUE(hostname, ip_address) ON CONFLICT IGNORE
        )
    ''')

    # Create the query_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS query_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_type TEXT,
            query_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            result_data TEXT
        )
    ''')

    # Create the smb_ns_hosts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS smb_ns_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE
        )
    ''')

    conn.commit()
    conn.close()

def save_query_results(query_type, results):
    """
    Saves the results of a query to the query_results table.

    :param query_type: The type of query (e.g., "list_dns").
    :param results: A list of tuples containing the query results.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Serialize results into JSON for storage
    result_data = json.dumps(results)
    
    cursor.execute('''
        INSERT INTO query_results (query_type, result_data)
        VALUES (?, ?)
    ''', (query_type, result_data))
    conn.commit()
    conn.close()

def get_saved_query_results(query_type=None):
    """
    Retrieves saved query results from the database.

    :param query_type: The type of query to filter by (optional).
    :return: A list of saved query results.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    if query_type:
        cursor.execute('''
            SELECT query_timestamp, result_data
            FROM query_results
            WHERE query_type = ?
        ''', (query_type,))
    else:
        cursor.execute('''
            SELECT query_type, query_timestamp, result_data
            FROM query_results
        ''')
    
    results = cursor.fetchall()
    conn.close()
    return results

def get_components():
    """
    Retrieves all components from the components table.

    :return: A list of tuples containing component data.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT component, hostname, ip_address
        FROM components
    ''')
    components = cursor.fetchall()
    conn.close()
    return components
