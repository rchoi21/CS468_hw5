import argparse
import sys
import socket
import threading
import paramiko

LOGFILE = 'logins.txt'
LOGFILE_LOCK = threading.Lock()
USERS = ["Amir71", "devin43", "joy67", "mike134", "sarah63"]

class SSHServerHandler (paramiko.ServerInterface):
    def __init__(self):
        self.counter = 0
        self.event = threading.Event()
        self.user = ""
    
    def get_user(self):
        return self.user

    def check_auth_password(self, username, password):
        if username not in USERS:
            return paramiko.AUTH_FAILED
        LOGFILE_LOCK.acquire()
        try:
            logfile_handle = open(LOGFILE,"a")
            print("New login: " + username + ":" + password)
            logfile_handle.write(username + ":" + password + "\n")
            logfile_handle.close()
            self.counter += 1
            self.user = username
        finally:
            LOGFILE_LOCK.release()
        if self.counter < 5:
            return paramiko.AUTH_FAILED
        else:
            self.counter = 0
            return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_request(self, kind, chanid):
        print(f"kind: {kind}, chanid: {chanid}")
        # logging.info('client called check_channel_request ({}): {}'.format(                  # WHY DOES THIS CLOSE THE CLIENT????????
        #             self.client_ip, kind))
        # print("what the")
        if kind == 'session':
            print("just checking if i get in here")
            return paramiko.OPEN_SUCCEEDED
        else:
            print("do i end up here???")
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        print(f"channel: {channel}")
        self.event.set()
        return True
    
    def check_channel_exec_request(self, channel, command):
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_ls(files):
    response = ""
    for file in files:
        response += file + " "
    return response

def handle_echo(cmd):
    idx = cmd.find(" ")
    if idx > 0:
        response = cmd[idx + 1:]
    else:
        response = "Unknown command: perhaps you mean \"echo <string>\"?"
    return response

def handle_cat(cmd):
    filename = cmd[3:]
    filename = filename.strip()
    if not filename.endswith(".txt"):
        return "Unknown file extension"
    try:
        f = open(filename, "r")
    except:
        return f"{filename} not found"
    response = f.read()
    f.close()
    return response
    
def handle_cp(cmd):
    cmd = cmd.strip()
    files = cmd.split(" ")
    files[0] = files[0].strip()
    files[1] = files[1].strip()
    if not files[0].endswith(".txt"):
        return "Unknown file extension"
    if not files[1].endswith(".txt"):
        return "Unknown file extension"
    print(f"source: {files[0]} dest: {files[1]}")
    try:
        f = open(files[0], "r")
    except:
        return f"{files[0]} not found"
    data = f.read()
    f.close()
    try:
        f2 = open(files[1], 'w')
    except:
        return f"Error when opening {files[1]}"
    f2.write(data)
    f2.close()
    return files[1]

    
def handle_cmd(cmd, sock, ip, files):
    response = ""
    if ">" in cmd:
        idx = cmd.find(">")
        filename = cmd[idx + 1:]
        filename = filename.strip()
        if filename.endswith(".txt"):
            try:
                f = open(filename, "w")
                if not filename in files:
                    files.append(filename)
                if cmd[:idx].startswith("ls"):
                    f.write(handle_ls(files))
                elif cmd[:idx].startswith("pwd"):
                    f.write("/home/root")
                elif cmd[:idx].startswith("echo"):
                    f.write(handle_echo(cmd[:idx]))
                elif cmd[:idx].startswith("cat"):
                    f.write(handle_cat(cmd[:idx]))
                f.close()
            except:
                response = f"Error while opening {filename}"
        else:
            response = "Unknown file extension"
    elif cmd.startswith("ls"):
        response = handle_ls(files)
    elif cmd.startswith("pwd"):
        response = "/home/root"
    elif cmd.startswith("echo"):
        response = handle_echo(cmd)
    elif cmd.startswith("cat"):
        response = handle_cat(cmd)
    elif cmd.startswith("cp"):
        filename = handle_cp(cmd[2:])
        if not filename in files:
            files.append(filename.strip())
    else:
        response = "Unknown command"
    print(files)

    if response != '':
        print('Response from honeypot ({}): '.format(ip, response))
        response = response + "\r\n"
    sock.send(response)
    

def handleConnection(client, host_key, ip):
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)

    server_handler = SSHServerHandler()
    transport.start_server(server=server_handler)
    channel = transport.accept(60) # timeout after 60s

    if channel is None:
        raise Exception("No channel")
    
    channel.settimeout(60) # timeout after 60s
    try:
        channel.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
        run = True
        user = server_handler.get_user()
        print(f"user: {user}")
        files = []
        while run:
            channel.send(user + "@" + ip + ":/$ ")
            command = ""
            while not command.endswith("\r"):
                transport = channel.recv(1024)
                print(ip + "- received:", transport)
                # Echo input to psuedo-simulate a basic terminal
                channel.send(transport)
                command += transport.decode("utf-8")
            channel.send("\r\n")
            command = command.rstrip()
            print('Command received ({}): {}'.format(ip, command))

            if command == "exit":
                print("Connection closed (via exit command): " + ip + "\n")
                run = False
            else:
                handle_cmd(command, channel, ip, files)

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass

    if not channel is None:
        channel.close()
    
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', default=22, dest="port")
    args = parser.parse_args()
    hostName = socket.gethostname()
    ipAddr = socket.gethostbyname(hostName) # 172.17.0.2

    # generate keys with 'ssh-keygen -t rsa -f server.key'
    host_key = paramiko.RSAKey(filename='server.key')

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # so that I can reuse sockets
        server_socket.bind((ipAddr, args.port))
        server_socket.listen(100)
        print(f"listening on {ipAddr}:{args.port}...")

        paramiko.util.log_to_file ('paramiko.log') 

        while(True):
            try:
                client_socket, client_addr = server_socket.accept()
                # thread.start_new_thread(handleConnection,(client_socket, host_key))
                client_handler = threading.Thread(target=handleConnection, args=(client_socket, host_key, ipAddr))
                client_handler.start()
            except Exception as e:
                print("ERROR: Client handling")
                print(e)
    except Exception as e:
        print("ERROR: Failed to create socket")
        print(e)
        sys.exit(1)

