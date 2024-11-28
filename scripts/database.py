import sqlite3
import os
import json

DB_FILE = os.path.join(os.getcwd(), "ad_enum.db")

def initialize_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create scan_results table
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

    # Create query_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS query_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_type TEXT,
            query_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            result_data TEXT
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
