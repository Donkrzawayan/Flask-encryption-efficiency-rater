import rsa as rsa


class Bob:
    def __init__(self):
        self._public, self._private = rsa.newkeys(2048)

    def get_public(self):
        return self._public

    def decode_message(self, message):
        return rsa.decrypt(message, self._private)


class Alice:
    def encrypt_message(self, message, public):
        return rsa.encrypt(message, public)


if __name__ == '__main__':
    bob = Bob()
    alice = Alice()
    public_key = bob.get_public()

    message = 'Hello World!'.encode('utf8')
    encrypted = alice.encrypt_message(message, public_key)
    print(encrypted)

    decrypted = bob.decode_message(encrypted)
    message = decrypted.decode('utf8')
    print(message)
