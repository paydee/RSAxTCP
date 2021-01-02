import socket
from deeRSA import gen_rsa_para, encrypt, decrypt

# generate RSA primitives
e = 65537
LENGTH = 512
n, d = gen_rsa_para(LENGTH)

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
    server_n = client.recv(1024).decode(FORMAT)
    server_d = client.recv(1024).decode(FORMAT)
    server_n = int(server_n, 10)
    server_d = int(server_d, 10)
    print(f"server n received {server_n}")
    print(f"server d received {server_d}")
    n_send = str(n) + "\n"
    d_send = str(d) + "\n"
    client.send(bytes(n_send, FORMAT))
    client.send(bytes(d_send, FORMAT))
    print(f"send n {n}")
    print(f"send d {d}")
    return server_n, server_d


def chat(server_n, server_d):
    out_mess = input("Enter mess: ")
    out_mess = encrypt(out_mess, n, e)
    client.send(bytes(out_mess, FORMAT))
    in_mess = client.recv(1024).decode(FORMAT)
    in_mess = decrypt(in_mess, server_n, server_d)
    print(f"Received message {in_mess} from server")






connected = True

while connected:
    server_n, server_d = exchange_key()
    # chat(server_n, server_d)
    # send(mess)
    # if mess == DISCONNECT_MESS:
    #     break
# send(n)
