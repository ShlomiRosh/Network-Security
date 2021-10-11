# Shalom Rosh, 308154418, Polina Rabinovich, 341095982
import sys
import base64
import struct
import socket
from time import sleep

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey,\
    _RSAPrivateKey

ENCODING = 'utf-8'
ROUND_INTERVAL = 60

"""######################## DATA TYPES ##########################"""


class SenderMessage:
    """
        This class represents a message loaded from the text file by the sender
    """

    def __init__(self, unparsed_message):
        # Pasring the message on seperate place to keep clean code
        splitted_message = unparsed_message.split(' ')
        self.message = bytes(splitted_message[0], ENCODING)
        self.path = self.path = [int(a)
                                 for a in splitted_message[1].split(',')]
        self.message_round = int(splitted_message[2])
        self.password = bytes(splitted_message[3], ENCODING)
        self.salt = bytes(splitted_message[4], ENCODING)
        self.dest_ip = Ip(splitted_message[5])
        self.dest_port = Port(int(splitted_message[6]))


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
        ip class that knows to perform the transformation easily
    """

    def __init__(self, port: int):
        self.port = port

    def as_bytes(self) -> bytes:
        return struct.pack('>H', self.port)


class MixServerData:
    """
        Class to manage each mix server details
    """

    def __init__(self, ip: Ip, port: Port, public_key: _RSAPublicKey):
        self.ip = ip
        self.port = port
        self.public_key = public_key


"""######################## ENCRYPTION ##########################"""


KEY_LENGTH = 32
ITERATIONS = 100000
PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


def generate_symmetric_key(password: bytes, salt: bytes):
    """
        Generates symmetric key for the symmetric encryption
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password))


def symmetric_encrypt(message: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(message)


def asymmetric_encrypt(message: bytes, public_key: _RSAPublicKey) -> bytes:
    return public_key.encrypt(message, PADDING)


def load_public_key(path: str) -> _RSAPublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return key


"""######################## COMMUNICATION #######################"""


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


"""######################## MAIN ################################"""


def generate_message(message: SenderMessage, mix_servers):
    """
    Generates the encrypted message with all the layers
    """

    # the first layer will be the symmetric encryption
    result = symmetric_encrypt(
        message.message,
        generate_symmetric_key(message.password, message.salt)
    )
    ip_to_encrypt = message.dest_ip
    port_to_encrypt = message.dest_port

    """
    for each mix server in the path we will encrypt the message and the address
    of the next station we iterate over the path in reversed order because
    we set the inner message first and every time we wrap it
    """
    for mix_id in reversed(message.path):
        message_to_encrypt = (ip_to_encrypt.as_bytes() +
                              port_to_encrypt.as_bytes() +
                              result)
        result = asymmetric_encrypt(
            message_to_encrypt, mix_servers[mix_id].public_key)
        ip_to_encrypt = mix_servers[mix_id].ip
        port_to_encrypt = mix_servers[mix_id].port
    return result


def send_message(message: SenderMessage, mix_servers):
    encrypted_message = generate_message(message, mix_servers)
    next_station = mix_servers[message.path[0]]
    tcp_send(encrypted_message, next_station.ip.ip, next_station.port.port)


def load_mix_servers(ips_path: str):
    """
        Loads the mix servers configuration
    """
    mix_servers = dict()
    with open(ips_path) as f:
        addresses = f.read().splitlines()
    for i, address in enumerate(addresses):
        ip = Ip(address.split(' ')[0])
        port = Port(int(address.split(' ')[1]))
        public_key = load_public_key(f'pk{i + 1}.pem')
        mix_servers[i + 1] = MixServerData(ip, port, public_key)
    return mix_servers


def load_messages(messages_path: str):
    """
        Loads all the messages from a given path
    """
    with open(messages_path) as f:
        raw_messages = f.readlines()
    return [SenderMessage(m) for m in raw_messages]


def send_messages_periodically(messages, mix_servers):
    """
        This function will send each interval of time
        the next messages to the mix server
    """
    # we sleep a bit in the start in order to prevent race condition with the start of the round
    sleep(ROUND_INTERVAL / 15)
    while messages:
        next_round_messages = []
        for m in messages:
            if m.message_round == 0:
                send_message(m, mix_servers)
            else:
                m.message_round -= 1
                next_round_messages.append(m)
        messages = next_round_messages
        sleep(ROUND_INTERVAL)


if __name__ == "__main__":
    message_number = int(sys.argv[1])
    mix_servers = load_mix_servers(r'ips.txt')
    messages = load_messages(f'messages{message_number}.txt')
    send_messages_periodically(messages, mix_servers)
