import hashlib
import Crypto
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import socket
import threading
import rsa

class AESCipher():
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

obj = AESCipher("KEY")

public_key, private_key = rsa.newkeys(1024)
public_partner = None

choice = input("Do you want to host (1) or to connect (2): ")

name = input("Please state the name of the person you wish to chat with : ")

print("\n\n--------This is the start of your chat with \"{0}\"--------\n\n".format(name))

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("172.28.240.1", 9999))
    server.listen()

    client, _ = server.accept()
    client.send(public_key.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("172.28.240.1", 9999))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key.save_pkcs1("PEM"))
else:
    exit()


def sending_messages(c):
    while True:
        message = input("")
        msg = obj.encrypt(message)
        c.send(rsa.encrypt(msg.encode(), public_partner))
        # c.send(message.encode())
        print("~You : "+ message)


def receiving_messages(c):
    while True:
        msg = rsa.decrypt(c.recv(1024), private_key).decode()
        print("~{0} : ".format(name)+ obj.decrypt(msg))
        # print("~{0} : ".format(name)+ c.recv(1024).decode())

threading.Thread(target=sending_messages, args=(client,)).start()
threading.Thread(target=receiving_messages, args=(client,)).start()
