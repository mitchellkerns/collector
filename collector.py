import os
import logging
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from importlib import import_module
from scripts.database import initialize_db
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Setup logging
LOG_FILE = "collector.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Define all commands for auto-completion
commands = [
    'list dns', 'list smb_ns', 'list domains', 'list dc', 'list components',
    'find domains', 'find ports', 'find dc', 'find components',
    'load nessuscsv', 'load nessusdb', 'load gnmap',
    'load xnmap', 'load targets',
    'enum users', 'enum adcs',
    'set auth', 'set interface', 'set targetdomain',
    'resetdb', 'exit'
]
command_completer = WordCompleter(commands, ignore_case=True)

# Command dispatcher
COMMANDS = {
    "list dns": "components.list_dns.list_dns",
    "list smbns": "components.list_smb_ns.list_smb_ns",
    "list domains": "components.list_domains.list_domains",
    "list dc": "components.list_dc.list_dc",
    "list components": "components.list_components.list_components",
    "find ports": "components.find_ports.find_ports",
    "find domains": "components.find_domains.find_domains",
    "find dns": "components.find_dns.find_dns",
    "find smbns": "components.find_smbns.find_smbns",
    "find dc": "components.find_dc.find_dc",
    "find components": "components.find_components.find_components",
    "load nessuscsv": "scripts.load_nessuscsv.load_nessuscsv",
    "load nessusdb": "scripts.load_nessusdb.load_nessusdb",
    "load gnmap": "scripts.load_gnmap.load_gnmap",
    "load xnmap": "scripts.load_xnmap.load_xnmap",
    "load targets": "scripts.load_targets.load_targets",
    "enum users": "components.enum_users.enum_users",
    "enum adcs": "components.enum_adcs.enum_adcs",
    "set auth": "components.set_auth.set_auth",
    "set interface": "components.set_interface.set_interface",
    "set targetdomain": "components.set_targetdomain.set_targetdomain",
    "resetdb": "components.resetdb.resetdb"
}

def execute_command(command, args):
    try:
        # Dynamically import and execute the mapped function
        module_name, function_name = COMMANDS[command].rsplit('.', 1)
        module = import_module(module_name)
        func = getattr(module, function_name)

        # Pass the arguments to the function
        func(*args)
    except KeyError:
        print(f"{Fore.RED}Unknown command.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Error executing command '{command}': {e}")
        print(f"{Fore.RED}An error occurred. Check {LOG_FILE} for details.{Style.RESET_ALL}")

def main():
    # Display ASCII Art and title
    ascii_art = rf"""
  {Fore.YELLOW}
  /$$$$$$            /$$ /$$                       /$$                        
 /$$__  $$          | $$| $$                      | $$                        
| $$  \__/  /$$$$$$ | $$| $$  /$$$$$$   /$$$$$$$ /$$$$$$    /$$$$$$   /$$$$$$ 
| $$       /$$__  $$| $$| $$ /$$__  $$ /$$_____/|_  $$_/   /$$__  $$ /$$__  $$
| $$      | $$  \ $$| $$| $$| $$$$$$$$| $$        | $$    | $$  \ $$| $$  \__/
| $$    $$| $$  | $$| $$| $$| $$_____/| $$        | $$ /$$| $$  | $$| $$      
|  $$$$$$/|  $$$$$$/| $$| $$|  $$$$$$$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$      
 \______/  \______/ |__/|__/ \_______/ \_______/   \___/   \______/ |__/      
                                                                           

    {Style.RESET_ALL}
    """
    print(ascii_art)

    print(f"{Fore.CYAN}{Style.BRIGHT}Active Directory Enumerator{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Commands:{Style.RESET_ALL}")
    print("  'load', 'list', 'find', 'enum', 'export', 'set', 'resetdb', 'exit'\n")

    # Initialize the database schema
    initialize_db()

    session = PromptSession(completer=command_completer)

    while True:
        try:
            # Use a plain prompt
            user_input = session.prompt('> ')
            if user_input.lower() == 'exit':
                print(f"{Fore.GREEN}Exiting...{Style.RESET_ALL}")
                break

            # Split the command and arguments
            parts = user_input.split()
            if not parts:
                continue

            # Handle multi-word commands and extract arguments
            base_command = ' '.join(parts[:2]) if ' '.join(parts[:2]) in COMMANDS else parts[0]
            args = parts[2:] if base_command in COMMANDS and len(parts) > 2 else parts[1:]

            if base_command in COMMANDS:
                execute_command(base_command, args)
            else:
                print(f"{Fore.RED}Unknown command.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}Exiting...{Style.RESET_ALL}")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            print(f"{Fore.RED}An unexpected error occurred. Check {LOG_FILE} for details.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
