import socket  # import the socket module
import termcolor  # import the termcolor module


def scan(target, ports):
    """
    Scan a target for open ports.

    Parameters:
    target (str): IP address or hostname of the target to scan.
    ports (int): Number of ports to scan.

    Returns:
    None
    """
    print(f"\n Starting scan for {str(target)}")
    for port in range(1, ports):
        scan_port(target, ports)


def scan_port(ip_addr, port):
    """
    Scan a single port on a target.

    Parameters:
    ip_addr (str): IP address or hostname of the target.
    port (int): Port number to scan.

    Returns:
    None
    """
    try:
        # create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set timeout to 1 second
        sock.settimeout(1)
        # attempt to connect to the target on the specified port
        result = sock.connect_ex((ip_addr, port))
        # if the connection was successful, print a message indicating that the port is open
        if result == 0:
            print(f'[+] Port opened {str(port)}')
        # close the socket
        sock.close()
    except socket.gaierror:
        # print an error message if the hostname could not be resolved
        print(f'[-] Could not resolve hostname {ip_addr}')
    except socket.error:
        # print an error message if the connection could not be established
        print(f'[-] Could not connect to the server {ip_addr}')


# prompt the user for a target or list of targets to scan
targets = input("[+] Enter targets to scan(split each ip address with a ,): ")
# prompt the user for the number of ports to scan
ports = int(input("[+] Enter number of ports to scan: "))
# check if the user has entered multiple targets
if ',' in targets:
    # if multiple targets were entered, print a message indicating that multiple targets will be scanned
    print(termcolor.colored('[*] Scanning multiple targets'), 'green')
    # loop through the list of targets and scan each one
    for ip_address in targets.split(','):
        scan(ip_address, ports)
# if only a single target was entered, scan that target
else:
    scan(targets, ports)
