import subprocess
import pystray
from PIL import Image
import platform
import json
import os
import logging
import sys
import psutil

process = None

ICONS_DIR = "icons"

ICON_OFF_PATH = os.path.join(ICONS_DIR, "icon-off.jpg")
ICON_ON_PATH = os.path.join(ICONS_DIR, "icon-on.png")

LOG_FILE_PATH = "app.log"
LOCK_FILE_PATH = "app.lock"

logging.basicConfig(filename=LOG_FILE_PATH, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def get_architecture():
    """Get sys arch"""
    arch = platform.architecture()[0]
    return 'x86_64' if arch == '64bit' else 'x86'


def load_config(config_path):
    """Get json settings"""
    try:
        with open(config_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f'Config file not found: {config_path}')
        logging.error(f'Config file not found: {config_path}')
        return {}
    except json.JSONDecodeError:
        print(f'Error decoding JSON from config file: {config_path}')
        logging.error(f'Error decoding JSON from config file: {config_path}')
        return {}


def build_command(config):
    """Creating a command line"""
    architecture = get_architecture()
    exe_path = f'{architecture}\\goodbyedpi.exe'

    command = [exe_path, '-9']

    if config.get('dns_addr'):
        command.extend(['--dns-addr', config['dns_addr']])
    if config.get('dns_port'):
        command.extend(['--dns-port', config['dns_port']])
    if config.get('dnsv6_addr'):
        command.extend(['--dnsv6-addr', config['dnsv6_addr']])
    if config.get('dnsv6_port'):
        command.extend(['--dnsv6-port', config['dnsv6_port']])

    for blacklist in config.get('blacklist', []):
        blacklist_path = os.path.basename(blacklist)
        command.extend(['--blacklist', blacklist_path])

    return command


def start_process(config_name):
    global process
    config_data = load_config('config.json')
    config = config_data.get(config_name, {})

    if not config:
        print(f'Config: "{config_name}" not found.')
        logging.error(f'Config: "{config_name}" not found.')
        return

    command = build_command(config)

    print(f'Executing command: {" ".join(command)}')
    logging.info(f'Executing command: {" ".join(command)}')

    if process:
        process.terminate()
        process.wait()

    try:
        process = subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW)
        print(f'Executed: {" ".join(command)}')
        logging.info(f'Executed: {" ".join(command)}')
    except Exception as e:
        print(f'Failed to start process: {e}')
        logging.error(f'Failed to start process: {e}')

    icon.icon = Image.open(ICON_ON_PATH)
    update_menu_for_running()


def stop_process(icon, item):
    global process
    if process:
        process.terminate()
        process.wait()
        print('The process has been successfully completed.')
        logging.info('The process has been successfully completed.')

    icon.icon = Image.open(ICON_OFF_PATH)
    update_menu_for_stopped()


def update_menu_for_running():
    global icon
    menu = pystray.Menu(
        pystray.MenuItem('Stop', stop_process),
        pystray.MenuItem('Exit', exit_program)
    )
    icon.menu = menu
    icon.update_menu()


def update_menu_for_stopped():
    global icon
    menu = pystray.Menu(
        pystray.MenuItem('Start Russia Blacklist', lambda icon, item: start_process('1_russia_blacklist')),
        pystray.MenuItem('Start Russia Blacklist DNS',
                         lambda icon, item: start_process('1_russia_blacklist_dnsredir')),
        pystray.MenuItem('Start Any Country', lambda icon, item: start_process('2_any_country')),
        pystray.MenuItem('Start Any Country DNS', lambda icon, item: start_process('2_any_country_dnsredir')),
        pystray.MenuItem('Exit', exit_program)
    )
    icon.menu = menu
    icon.update_menu()


def exit_program(icon, item):
    if process:
        process.terminate()
        process.wait()
        print('Process terminated on exit.')
        logging.info('Process terminated on exit.')

    if os.path.exists(LOCK_FILE_PATH):
        os.remove(LOCK_FILE_PATH)

    icon.stop()


def create_icon():
    icon_image = Image.open(ICON_OFF_PATH)
    menu = pystray.Menu(
        pystray.MenuItem('Start Russia Blacklist', lambda icon, item: start_process('1_russia_blacklist')),
        pystray.MenuItem('Start Russia Blacklist DNS',
                         lambda icon, item: start_process('1_russia_blacklist_dnsredir')),
        pystray.MenuItem('Start Any Country', lambda icon, item: start_process('2_any_country')),
        pystray.MenuItem('Start Any Country DNS', lambda icon, item: start_process('2_any_country_dnsredir')),
        pystray.MenuItem('Exit', exit_program)
    )
    icon = pystray.Icon("goodbyedpi", icon_image, "GoodByeDPI", menu=menu)
    return icon


def get_existing_pid():
    """Get the PID from the lock file, if it exists."""
    if os.path.exists(LOCK_FILE_PATH):
        with open(LOCK_FILE_PATH, 'r') as lock_file:
            pid = lock_file.read().strip()
            return int(pid) if pid.isdigit() else None
    return None


def is_process_running(pid):
    """Check if a process with the given PID is currently running."""
    try:
        process = psutil.Process(pid)
        return process.is_running()
    except psutil.NoSuchProcess:
        return False


def check_if_running():
    """Check if another instance is running by checking the lock file."""
    pid = get_existing_pid()
    if pid and is_process_running(pid):
        return True
    return False


def create_lock_file():
    """Create a lock file with the current process ID."""
    with open(LOCK_FILE_PATH, 'w') as lock_file:
        lock_file.write(str(os.getpid()))


if __name__ == "__main__":
    if check_if_running():
        print("Another instance is already running.")
        sys.exit(1)

    create_lock_file()

    print("Starting the application...")
    logging.info('Application started.')

    icon = create_icon()
    icon.run()

    print("Application has stopped.")
    logging.info('Application has stopped.')

    if os.path.exists(LOCK_FILE_PATH):
        os.remove(LOCK_FILE_PATH)
