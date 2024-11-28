import sqlite3
import os
from scripts.database import initialize_db, DB_FILE, get_saved_query_results
from scripts.nessus_parser import parse_nessus_csv
from components.list_dns import list_dns
from components.find_domains import find_domains


def load_nessus_csv(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return
    
    print(f"Loading Nessus CSV: {filepath}")
    results = parse_nessus_csv(filepath)
    
    if not results:
        print("No valid data found in the CSV.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    imported = 0

    for result in results:
        try:
            cursor.execute('''
                INSERT INTO scan_results (cve, ip_address, protocol, port, name, synopsis, plugin_output)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', result)
            imported += 1
        except sqlite3.IntegrityError:
            pass  # Ignore duplicates
    
    conn.commit()
    conn.close()

    print(f"Imported {imported} results into the database.")

def view_saved_results():
    results = get_saved_query_results()
    if results:
        print("Saved Query Results:")
        for query_type, timestamp, result_data in results:
            print(f"[{timestamp}] {query_type}: {result_data}")
    else:
        print("No saved query results found.")

def main():
    initialize_db()
    print("Active Directory Enumerator")
    print("Commands: 'list dns', 'load nessuscsv <filepath>', 'find domains', 'view results', 'exit'")
    
    while True:
        command = input("> ").strip()

        if command.lower() == "list dns":
            list_dns()
        elif command.lower().startswith("load nessuscsv"):
            parts = command.split(" ", 2)
            if len(parts) < 3:
                print("Usage: load nessuscsv <filepath>")
            else:
                filepath = parts[2].strip().strip("'\"")
                load_nessus_csv(filepath)
        elif command.lower() == "find domains":
            find_domains()
        elif command.lower() == "view results":
            view_saved_results()
        elif command.lower() == "exit":
            print("Exiting...")
            break
        else:
            print("Unknown command. Try 'list dns', 'load nessuscsv <filepath>', 'find domains', 'view results', or 'exit'.")


if __name__ == "__main__":
    main()
