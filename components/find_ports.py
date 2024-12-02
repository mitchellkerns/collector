import sqlite3
import logging
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread, Lock
from queue import Queue
from colorama import Fore, Style
from scripts.database import DB_FILE

# Define ports and their corresponding names
PORTS = {
    53: "DNS Server Detection",
    445: "Microsoft Windows SMB Service Detection"
}

# Lock for database operations
db_lock = Lock()

def scan_port(ip, port, timeout_seconds=1):
    """
    Scans a single port on a given IP address.
    :param ip: The IP address to scan.
    :param port: The port to scan.
    :param timeout_seconds: Timeout for the connection attempt.
    :return: True if the port is open, False otherwise.
    """
    try:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(timeout_seconds)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception as e:
        logging.error(f"Error scanning port {port} on {ip}: {e}")
        return False

def worker(queue, results, timeout_seconds=1):
    """
    Worker thread function to process the queue.
    :param queue: Queue of (IP, port) to scan.
    :param results: Shared list to store results.
    :param timeout_seconds: Timeout for scanning.
    """
    while not queue.empty():
        try:
            ip, port = queue.get_nowait()
            if scan_port(ip, port, timeout_seconds):
                logging.info(f"Port {port} open on {ip}")
                results.append((ip, port, PORTS[port]))
                print(f"{Fore.GREEN}Port {port} open on {ip} - {PORTS[port]}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error in worker thread: {e}")
        finally:
            queue.task_done()

def find_ports(*args):
    """
    Finds open ports (53 and 445) for all IP addresses in the database and stores results.
    """
    logging.info("Starting threaded port scan for DNS and SMB services...")
    print(f"{Style.BRIGHT}{Fore.CYAN}Starting port scan for DNS and SMB services...{Style.RESET_ALL}")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        # Retrieve all unique IP addresses from the database
        cursor.execute("SELECT DISTINCT ip_address FROM scan_results WHERE ip_address IS NOT NULL")
        ip_addresses = [row[0] for row in cursor.fetchall()]

        if not ip_addresses:
            print(f"{Fore.RED}No IP addresses found in the database to scan.{Style.RESET_ALL}")
            return

        # Prepare threading
        queue = Queue()
        results = []
        threads = []
        num_threads = 10  # Number of threads to use

        # Populate queue with (IP, port) pairs
        for ip in ip_addresses:
            for port in PORTS.keys():
                queue.put((ip, port))

        # Start threads
        for _ in range(num_threads):
            thread = Thread(target=worker, args=(queue, results))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        queue.join()
        for thread in threads:
            thread.join()

        # Insert results into the database
        with db_lock:
            cursor.executemany('''
                INSERT OR IGNORE INTO scan_results (
                    ip_address, protocol, port, name, cve, synopsis, plugin_output
                ) VALUES (?, 'tcp', ?, ?, NULL, NULL, NULL)
            ''', results)
            conn.commit()

        print(f"{Fore.YELLOW}Port scanning complete. {len(results)} services detected.{Style.RESET_ALL}")
        logging.info(f"Port scanning complete. {len(results)} services detected.")
    except Exception as e:
        logging.error(f"Error during port scanning: {e}")
        print(f"{Fore.RED}Error during port scanning: {e}{Style.RESET_ALL}")
    finally:
        conn.close()
