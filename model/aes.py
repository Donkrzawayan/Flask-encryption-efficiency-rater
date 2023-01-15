import hashlib
from base64 import b64encode, b64decode
import sys

from Cryptodome import Random
from Cryptodome.Cipher import AES


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def encode_file_yield(self, plain_text):
        data = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        step = 0
        while True:
            # Read self.block_size characters at a time.
            s = data[step * self.block_size:(step + 1) * self.block_size]
            if not s:
                break
            # Encrypt with RSA and append the result to list.
            # RSA encryption returns a tuple containing 1 string, so i fetch the string.
            yield b64encode(iv + cipher.encrypt(s.encode())).decode("utf-8")
            step += 1

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def decode_file_yield(self, encrypted_text):
        data = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        step = 0
        while True:
            # Read self.block_size characters at a time.
            s = data[step * self.block_size:(step + 1) * self.block_size]
            if not s:
                break
            # Encrypt with RSA and append the result to list.
            # RSA encryption returns a tuple containing 1 string, so i fetch the string.
            yield self.__unpad(cipher.decrypt(s).decode("utf-8"))
            step += 1


if __name__ == "__main__":
    print(sys.argv[1])
    input_file = sys.argv[1]
    cipher = AESCipher("super_key_belonging_to_piotr")
    data = open(input_file).read()
    encrypted_data = cipher.encrypt(data)
    decrypted_data = cipher.decrypt(encrypted_data)
    encrypted_text_file = open('encrypted_' + input_file, 'wb+')
    encrypted_text_file.write(bytes(encrypted_data, 'utf-8'))
    encrypted_text_file.close()
    decrypted_text_file = open('decrypted_' + input_file, 'wb+')
    decrypted_text_file.write(bytes(decrypted_data, 'utf-8'))
    decrypted_text_file.close()
