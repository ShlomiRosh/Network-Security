# Shalom Rosh, 308154418, Polina Rabinovich, 341095982
import sys
import socket
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ENCODING = 'utf-8'


"""######################## ENCRYPTION ##########################"""

KEY_LENGTH = 32
ITERATIONS = 100000


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


def symmetric_decrypt(cipher: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.decrypt(cipher)


"""######################## COMMUNICATION #######################"""


MAX_CLIENTS_ON_QUEUE = 2048
RECV_BUFFER = 4096


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
        This function creates a server that runs func() on each
        message that is being recieved
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
        # In order to prevent resource leaks
        sock.close()


"""######################## MAIN ################################"""


def handle_message(cipher: bytes):
    global symmetric_key
    message = symmetric_decrypt(cipher, symmetric_key)
    print(f'{message.decode()} {datetime.now().strftime("%H:%M:%S")}')


if __name__ == "__main__":
    global symmetric_key
    password = bytes(sys.argv[1], ENCODING)
    salt = bytes(sys.argv[2], ENCODING)
    port = int(sys.argv[3])
    symmetric_key = generate_symmetric_key(password, salt)

    server_handler(handle_message, port)
