import rsa as rsa


class Bob:
    def __init__(self):
        self._public, self._private = rsa.newkeys(2048)

    def get_public(self):
        return self._public

    def get_private(self):
        return self._private

    def decode_message(self, message):
        return rsa.decrypt(message, self._private)


class Alice:
    def encrypt_message(self, message, public):
        return rsa.encrypt(message, public),


class GenerationOfKeys:
    def __init__(self, public, private):
        self._public = public
        self._private = private

    def get_public(self):
        return self._public

    def get_private(self):
        return self._private


def encode_file(GenerationOfKeys):
    data = open('1.txt').read()
    print(data)

    step = 0
    new_file = open('temp.txt', 'wb+')
    while 1:
        # Read 128 characters at a time.
        s = data[step * 128:(step + 1) * 128]
        if not s: break
        print(s)
        # Encrypt with RSA and append the result to list.
        # RSA encryption returns a tuple containing 1 string, so i fetch the string.
        to_add = rsa.encrypt(s.encode('utf8'), GenerationOfKeys.get_public())
        print(to_add)
        new_file.write(to_add)
        step += 1

def decode_file(GenerationOfKeys):
    opened_file = open('temp.txt', mode='rb').read()
    step = 0
    new_file = open('wynikowy.txt', 'w+')
    while 1:
        # Read 128 characters at a time.
        s = opened_file[step * 128:(step + 1) * 128]  # max do 127 znakow - dorobić padding
        if not s: break
        print(s)
        # Encrypt with RSA and append the result to list.
        # RSA encryption returns a tuple containing 1 string, so i fetch the string.
        to_add = rsa.decrypt(s, GenerationOfKeys.get_private())
        message = to_add.decode('utf8')

        print(message)
        new_file.write(message)
        step += 1


def generate_key():
    public, private = rsa.newkeys(2048)
    pukey = open('publicKey.key', 'wb')
    pukey.write(public.save_pkcs1('PEM'))
    pukey.close()
    prkey = open('privateKey.key', 'wb')
    prkey.write(private.save_pkcs1('PEM'))
    prkey.close()


def working_encryption():
    opened_file = open('temp.txt', mode='rb').read()
    to_add = rsa.decrypt(opened_file, GenerationOfKeys.get_private())
    message = to_add.decode('utf8')

    print(message)
    new_file = open('wynikowy.txt', 'w+')
    new_file.write(message)


if __name__ == '__main__':
    generate_key()
    with open('privateKey.key', mode='rb') as privatefile:
        keydata = privatefile.read()

    private_key = rsa.PrivateKey.load_pkcs1(keydata)

    with open('publicKey.key', mode='rb') as publicKey:
        keydata2 = publicKey.read()

    public_key = rsa.PublicKey.load_pkcs1(keydata2)

    GenerationOfKeys = GenerationOfKeys(public_key, private_key)
    encode_file(GenerationOfKeys)
    decode_file(GenerationOfKeys)
    # working_encryption()
