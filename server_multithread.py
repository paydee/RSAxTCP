import socket
import threading
from deeRSA import gen_key, encrypt, decrypt
import re
import utils

# generate RSA primitives
e = 65537
length = 512
n, d = gen_key(length)
public_key = {'n': n, 'd': d}
private_keys = {'n': n, 'e': e}

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


def server_run():
    server.listen()
    print(f"[LISTENING] Server is listening on {server}")
    while True:
        try:

            clientsocket, addr = server.accept()
            print(f"[CONNECTED] Connected to {addr}")
            client_keys = exchange_key(clientsocket)
            chat(clientsocket, client_keys)
            break

        except Exception as e:
            raise Exception(f"Connect failed {e.args}")
    print(f"[DISCONNECT] Sever disconnect to {addr}")
    clientsocket.close()


def exchange_key(client):
    """ Send this socket's public key to the connecting socket, receiver the connecting socket's public key
    :param client: the connecting socket
    :return: RSA public keys of connecting socket
    """
    mess = str(public_key)
    utils.send(mess, client)
    mess_in = utils.recv_full_mess(client)
    client_n, client_d = re.findall(r"\d+", mess_in)
    client_keys = {'n': int(client_n), 'd': int(client_d)}
    return client_keys


# mess: string -> send mess in RSA encryption

def send_mess_RSA(mess, socket, keys):
    """ Send message in arbitrary size with RSA encryption
    :param mess: the message to send. Must be a  string in arbitrary size
    :param socket: socket which fire the sending
    :param keys: private keys for RSA encryption
    :return: None
    """
    b_mess = bytes(mess, FORMAT)
    key_len = utils.byte_size(keys['n'])
    mess_len = len(b_mess)
    if mess_len >= key_len - 11:
        max_chunk = key_len - 11
        chunks = [b_mess[i: (i + max_chunk)] for i in range(0, mess_len, max_chunk)]
        chunks.append(b_mess[-(mess_len % max_chunk):])
        full_mess = []
        for chunk in chunks:
            x = encrypt(chunk, keys['n'], e)
            full_mess.append(x)
        full_mess = b''.join(full_mess)
        len_mess = f'{len(full_mess):<{HEADER}}'
        full_mess = len_mess.encode(FORMAT) + full_mess
        socket.send(full_mess)
    else:
        mess = encrypt(b_mess, keys['n'], e)
        len_mess = f'{len(mess):<{HEADER}}'
        mess = bytes(len_mess, FORMAT) + mess
        socket.send(mess)


# data: bytes --->  decrypted mess : string
def recv_full_mess_RSA(socket, keys):
    """ Receive message encrypted with RSA in arbitrary size, decrypt it and return plaintext string

   :param socket: the socket to receive the message
   :param keys: public keys of the sender to decrypt message
   :return: plaintext string of decrypted message in arbitrary size
   """
    full_mess = b''
    key_len = utils.byte_size(keys['n'])
    new_mess = True
    mess = socket.recv(HEADER).decode(FORMAT)
    while True:
        if new_mess:
            len_mess = int(mess[:HEADER])
            new_mess = False
        mess = socket.recv(HEADER)
        full_mess += mess
        decrypted_mess = []
        if len(full_mess) == len_mess:
            if len_mess > key_len:
                len_chunk = key_len
                chunks = [full_mess[i: (i + len_chunk)] for i in range(0, len_mess, len_chunk)]
                for chunk in chunks:
                    decrypted_mess.append(decrypt(chunk, keys['n'], keys['d']).decode(FORMAT))
                return "".join(decrypted_mess)
            else:
                return decrypt(full_mess, keys['n'], keys['d']).decode(FORMAT)


def listen(client, client_keys):
    """ Socket stay constantly receive data from connecting socket,
   if a message sent, it receives the message and print to the console

   :param client: connecting socket
   :param client_keys: RSA public keys of connecting socket
   """
    while True:
        in_mess = recv_full_mess_RSA(client, client_keys)
        if in_mess == DISCONNECT_MESS:
            print(f"Other> {in_mess}")
            out_mess = input("Me> ")
            send_mess_RSA(out_mess, client, private_keys)
            break
        print(f"Other> {in_mess}")


def answer(client, client_keys):
    """Socket stay constantly send data to connecting socket,
   if a message receive from console of the socket, it send the message
   to the connecting socket

   :param client: connecting socket
   :param client_keys: RSA public keys of connecting socket
   :return:
   """
    while True:
        out_mess = input("\nMe> ")
        if out_mess == DISCONNECT_MESS:
            send_mess_RSA(out_mess, client, private_keys)
            in_mess = recv_full_mess_RSA(client, client_keys)
            print(f"\nOther> {in_mess}")
            break
        send_mess_RSA(out_mess, client, private_keys)

    # chat with RSA encrypted mess


def chat(client, client_keys):
    """Multi threading listen and answer to support multi message sending
    and receiving
    """
    out_mess = "hi"
    send_mess_RSA(out_mess, client, private_keys)
    while True:
        listen(client, client_keys)
        threading.Thread(target=answer, args=(client, client_keys)).start()


print("[STARTING] server is starting")
server_run()
