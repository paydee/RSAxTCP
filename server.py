import socket
import sys
import threading
from deeRSA import gen_rsa_para, encrypt, decrypt

# generate RSA primitives
e = 65537
length = 512
n, d = gen_rsa_para(length)

# connection's constants
BUFFER = 1024
HEADER = 64
PORT = 8790
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = "utf-8"
DISCONNECT_MESS = "DISCONNECT!"

# create server socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)





# handle client behavior
# def handle_client(conn, addr):
#     print(f"NEW CONNECTIONS {addr} connected")
#
#     connected = True
#     while connected:
#         msg_len = conn.recv(HEADER).decode(FORMAT)
#         if msg_len:
#             msg_len = int(msg_len)
#             msg = conn.recv(msg_len).decode(FORMAT)
#             if msg == DISCONNECT_MESS:
#                 connected = False
#                 print("DISCONNECT!")
#             print(f"[{addr} {msg}]")
#             conn.send("Message received".encode(FORMAT))
#     print("still listening")
#     conn.close()


def start():
    server.listen()
    print(f"[LISTENNING] Server is listening on {server}")
    while True:
        print(sys.stderr, 'waiting for a connection')
        clientsocket, addr = server.accept()
        client_n, client_d = exchange_key(clientsocket)
        # TODO: input length of key


# TODO: exchange RSA primitives
def exchange_key(client):
    n_send = str(n) + '\n'
    d_send = str(d) + '\n'
    client.send(bytes(n_send, FORMAT))
    client.send(bytes(d_send, FORMAT))
    client_n = client.recv(1024).decode(FORMAT)
    client_d = client.recv(1024).decode(FORMAT)
    client_n = int(client_n, 10)
    client_d = int(client_d, 10)
    print(f"n {n}\n d {d}\n client_n {client_n} \n client_d {client_d} \n")
    return client_n, client_d

# TODO: chat with RSA encrypted mess
def chat(client, client_n, client_d):
    in_mess = client.recv().decode(FORMAT)
    in_mess = decrypt(in_mess, client_n, client_d)
    print(f"Client> {in_mess} from client")
    out_mess = input("Me> ")
    out_mess = encrypt(out_mess, n, e)
    client.send(bytes(out_mess, FORMAT))

# def chat(clientsocket):
#     while True:


print("[STARTING] server is starting ...")
start()
