import json
import socket
from utils import byte_size
from deeRSA import gen_key, encrypt, decrypt

# generate RSA primitives
e = 65537
LENGTH = 512
n, d = gen_key(LENGTH)
bit_order = 'big'

# connection's constants
HEADER = 64
PORT = 8790
FORMAT = "utf-8"
DISCONNECT_MESS = "DISCONNECT!"
SERVER = "127.0.1.1"
ADDR = (SERVER, PORT)

# create client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


# TODO: exchange RSA primitives
# TODO: chat with RSA encrypted mess

# handling mess

def send(msg):
    mess = msg.encode(FORMAT)
    msg_len = len(mess)
    send_len = str(msg_len).encode(FORMAT)
    send_len += b' ' * (HEADER - len(send_len))
    client.send(send_len)
    client.send(mess)
    print(client.recv(2048).decode(FORMAT))


def exchange_key():
    info = json.loads(client.recv(2048).decode(FORMAT))
    print("sending......")
    server_n = info.get("client_n")
    server_d = info.get("client_d")
    print(f"server n received {server_n}")
    print(f"server d received {server_d}")
    client_info = {
        "client_n": n,
        "client_d": d
    }
    client.send(json.dumps(client_info).encode(FORMAT))
    print(f"send n {n}")
    print(f"send d {d}")
    return server_n, server_d


def chat(server_n, server_d):
    out_mess = input("Me> ")
    out_mess = encrypt(bytes(out_mess, FORMAT), n, e)
    client.send(bytes(out_mess, FORMAT))
    in_mess = client.recv(1024).decode(FORMAT)
    in_mess = decrypt(in_mess, server_n, server_d).decode(FORMAT)
    print(f"Other> {in_mess}")


connected = True

while connected:
    server_n, server_d = exchange_key()
    chat(server_n, server_d)
    # send(mess)
    # if mess == DISCONNECT_MESS:
    #     break
# send(n)
