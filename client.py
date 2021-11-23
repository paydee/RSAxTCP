import socket
import re
from deeRSA import gen_key, encrypt, decrypt
import utils

# generate RSA primitives
e = 65537
LENGTH = 512  # size in bit
n, d = gen_key(LENGTH)
pubic_key = {'n': n, 'd': d}

private_keys = {'n': n, 'e': e}
# connection's constants
HEADER = 64
PORT = 8791
FORMAT = "utf-8"
DISCONNECT_MESS = "DISCONNECT!"
SERVER = "127.0.1.1"
ADDR = (SERVER, PORT)


# exchange RSA keys
def exchange_key(socket):
    """Send this socket's public key to the connecting socket, receiver the connecting socket's public key

    :param socket: the connecting socket
    :return: RSA public keys of connecting socket
    """
    mess_in = utils.recv_full_mess(socket)
    server_n, server_d = re.findall(r"\d+", mess_in)
    server_keys = {'n': int(server_n), 'd': int(server_d)}
    mess_out = str(pubic_key)
    utils.send(mess_out, socket)
    return server_keys


# data in: bytes --->  decrypted mess : string
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


def chat(server_key):
    while True:
        in_mess = recv_full_mess_RSA(client, server_key)
        if in_mess == DISCONNECT_MESS:
            print(f"Other> {in_mess}")
            out_mess = input("Me> ")
            send_mess_RSA(out_mess, client, private_keys)
            break
        print(f"Other> {in_mess}")
        out_mess = input("Me> ")
        if out_mess == DISCONNECT_MESS:
            send_mess_RSA(out_mess, client, private_keys)
            in_mess = recv_full_mess_RSA(client, server_key)
            print(f"Other> {in_mess}")
            break
        send_mess_RSA(out_mess, client, private_keys)
        print("MESS SENT!!!")


try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[CREATE] Client socket created")
    connected = True
    try:
        client.connect(ADDR)
        print(f"[CONNECT] Client connects to {ADDR}")
        while connected:
            server_keys = exchange_key(client)
            chat(server_keys)
            connected = False
        print(f"[DISCONNECT] Client disconnect to {ADDR}")

        client.close()
    except Exception as e:
        raise Exception(f"Connect failed {e.args}")
except Exception as e:
    raise Exception(f"Socket can't be created {e.args}")
