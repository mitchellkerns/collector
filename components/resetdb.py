import sqlite3
import os
from scripts.database import DB_FILE
import logging
from colorama import Fore, Style

def resetdb(*args):
    """
    Clears all data from the database, including resetting auto-increment counters.
    """
    try:
        if os.path.exists(DB_FILE):
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            # Dynamically retrieve and clear all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                if table.startswith("sqlite_"):
                    continue  # Skip internal SQLite tables
                cursor.execute(f"DELETE FROM {table};")
                cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}';")  # Reset auto-increment IDs

            conn.commit()
            conn.close()

            logging.info("Database reset successfully. All data cleared.")
            print(f"{Fore.GREEN}Database reset successfully. All data cleared.{Style.RESET_ALL}")
        else:
            logging.warning(f"Database file {DB_FILE} does not exist.")
            print(f"{Fore.YELLOW}Database file {DB_FILE} does not exist. Nothing to reset.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error resetting database: {e}")
        print(f"{Fore.RED}An error occurred while resetting the database. Check logs for details.{Style.RESET_ALL}")
