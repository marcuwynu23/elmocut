from scapy.all import conf, get_if_list, get_if_hwaddr
from subprocess import check_output, CalledProcessError
from socket import socket
from threading import Thread
from manuf import manuf

from models.ifaces import NetFace
from constants import *

# Compatibility patch for Scapy ≥ 2.5.x (get_windows_if_list moved)
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    def get_windows_if_list():
        # Fallback: return an empty list if not on Windows or function missing
        return []

p = manuf.MacParser()


def terminal(command, shell=True, decode=True):
    """Run a terminal command and return its decoded output."""
    try:
        cmd = check_output(command, shell=shell)
        return cmd.decode() if decode else None
    except CalledProcessError:
        return None
    except UnicodeDecodeError:
        return str(cmd)


def threaded(fn):
    """Decorator to run a function in a separate thread."""
    def run(*k, **kw):
        t = Thread(target=fn, args=k, kwargs=kw)
        t.start()
        return t
    return run


def get_vendor(mac):
    """Get vendor from Wireshark’s manuf MAC database."""
    return p.get_manuf(mac) or 'None'


def good_mac(mac):
    """Normalize MAC address (dash-separated → colon-separated)."""
    return mac.upper().replace('-', ':')


def get_my_ip(iface_name):
    """Get local IP address for a given interface."""
    response = terminal(f'netsh interface ip show address "{iface_name}" | findstr "IP"')
    return response.split()[-1] if response else '127.0.0.1'


def get_gateway_ip(iface_name):
    """Get gateway IP for a given interface."""
    response = terminal(f'netsh interface ip show address "{iface_name}" | findstr /i default')
    return response.split()[-1] if response else '0.0.0.0'


def get_gateway_mac(iface_ip, router_ip):
    """Get the MAC address of the gateway."""
    response = terminal(f'arp -a {router_ip} -N {iface_ip} | findstr "dynamic static"')
    try:
        return good_mac(response.split()[1])
    except Exception:
        return GLOBAL_MAC


def goto(url):
    """Open URL in default browser."""
    terminal(f'start "" "{url}"')


def check_connection(func):
    """Decorator: only run the function if the system is connected to a network."""
    def wrapper(*args, **kargs):
        if is_connected():
            return func(args[0])
    return wrapper


def get_ifaces():
    """Yield active network interfaces."""
    conf.route.resync()
    pcap = [net.split('_')[-1] for net in get_if_list()]
    for iface in get_windows_if_list():
        if iface.get('guid') in pcap and iface.get('ips'):
            yield NetFace(iface)


def get_default_iface():
    """Get the default (active) interface."""
    for iface in get_ifaces():
        if iface.guid in str(conf.iface):
            return iface
    return NetFace(DUMMY_IFACE)


def get_iface_by_name(name):
    """Find an interface by its name."""
    for iface in get_ifaces():
        if iface.name == name:
            return iface
    return get_default_iface()


def is_connected(current_iface=None):
    """Check if the system is connected to any network."""
    if current_iface is None:
        current_iface = get_default_iface()

    if current_iface.name == 'NULL':
        return False

    ipconfig_output = terminal('ipconfig | findstr /i gateway')
    if ipconfig_output is not None:
        return any(i.isdigit() for i in ipconfig_output)

    # Fallback if ipconfig fails
    try:
        socket().connect(('8.8.8.8', 53))
        return True
    except Exception:
        return False
