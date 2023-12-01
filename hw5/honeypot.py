import argparse
import socket
import paramiko

def start_server(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((ip, port))
    sock.listen(5)
    print(f"listening on {ip}:{port}...")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', default=22, dest="port")
    args = parser.parse_args()
    hostName = socket.gethostname()
    ipAddr = socket.gethostbyname(hostName) # 172.17.0.2
    start_server(ipAddr, args.port)

