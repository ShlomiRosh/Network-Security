# Shalom Rosh, 308154418, Polina Rabinovich, 341095982
import sys
import struct
import socket
from time import sleep
from threading import Thread
from queue import SimpleQueue

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, \
    _RSAPrivateKey

ROUND_INTERVAL = 60
IPS_FILE_PATH = 'ips.txt'

"""######################## DATA TYPES ##########################"""


class Ip:
    """
        ip class that knows to perform the transformation easily
    """

    def __init__(self, ip: str):
        self.ip = ip

    def as_bytes(self) -> bytes:
        values = [int(i) for i in self.ip.split('.')]
        return bytes(values)


class Port:
    """
        port class that knows to perform the transformation easily
    """

    def __init__(self, port: int):
        self.port = port

    def as_bytes(self) -> bytes:
        return struct.pack('>H', self.port)


class MixMessage:
    """
        message in the mix server after decryption
    """

    def __init__(self, message: bytes):
        # unpacking the ip address from the
        self.ip = Ip('.'.join([str(i)
                     for i in struct.unpack('BBBB', message[:4])]))

        # returns tuple with one element
        port_value, = struct.unpack('>H', message[4:6])
        self.port = Port(port_value)
        self.message = message[6:]


"""######################## ENCRYPTION ##########################"""


KEY_LENGTH = 32
ITERATIONS = 100000
PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


def asymmetric_decrypt(cipher: bytes, private_key: _RSAPrivateKey) -> bytes:
    return private_key.decrypt(cipher, PADDING)


def load_private_key(path: str) -> _RSAPrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return key


"""######################## COMMUNICATION #######################"""


MAX_CLIENTS_ON_QUEUE = 2048
RECV_BUFFER = 4096


def tcp_send(data, ip, port):
    """
        Sends data fully using tcp to the requested address
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        sock.sendall(data)
    finally:
        sock.close()


def recvall(sock: socket.socket):
    """
        Reads the message until the end of it from a given socket
    """
    message = b''
    while True:
        try:
            chunk = sock.recv(RECV_BUFFER)
            message += chunk
            if len(chunk) < RECV_BUFFER:
                break
        except socket.error:
            break
    return message


def server_handler(func, port):
    """
        This function creates a server that runs func() on each message
        that is being recieved
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", port))
        sock.listen(MAX_CLIENTS_ON_QUEUE)
        while True:
            client, _ = sock.accept()
            message = recvall(client)
            func(message)
    finally:
        # In order to keep all ports closed
        sock.close()


"""######################## MAIN ################################"""


def incoming_messages_listener(port: int, q: SimpleQueue):
    """
        Process that will get messages and put them in the queue
        (in order for the mix to read them on time)
    """
    server_handler(q.put, port)


def get_messages_from_queue(q: SimpleQueue):
    """
        Reads all the messages from the queue in order to
    """
    messages = []

    """
    Note: we use the queue size instead of while q.empty() in order to prevent race condition 
    in the case of inserting items while trying to insert more messages to the queue
    """
    for _ in range(q.qsize()):
        messages.append(q.get())
    return messages


def send_messages(q: SimpleQueue):
    """
        Process that sends messages every round
    """
    private_key = load_private_key(f'sk{sys.argv[1]}.pem')
    while True:
        sleep(ROUND_INTERVAL)
        for encrypted_message in get_messages_from_queue(q):
            message = MixMessage(asymmetric_decrypt(
                encrypted_message, private_key))
            tcp_send(message.message, message.ip.ip, message.port.port)


def get_server_port(ips_path: str, server_id: int):
    """
        finds the server port
    """
    with open(ips_path) as f:
        addresses = f.read().splitlines()
    # -1 because the server ids starts from one and the file lines from zero
    _, port = addresses[server_id - 1].split()
    return int(port)


if __name__ == "__main__":
    # This queue will hold the message until sending them to the clients
    q = SimpleQueue()
    port = get_server_port(IPS_FILE_PATH, int(sys.argv[1]))

    server_thread = Thread(target=incoming_messages_listener, args=(port, q))
    round_message_dispatcher = Thread(target=send_messages, args=(q, ))

    server_thread.start()
    round_message_dispatcher.start()
