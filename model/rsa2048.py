import rsa as rsa


class GenerationOfKeys:
    def __init__(self, public, private):
        self._public = public
        self._private = private

    def get_public(self):
        return self._public

    def get_private(self):
        return self._private


def encode_file(generation_of_keys, input_file):
    data = open(input_file).read()
    step = 0
    new_file = open('encoded_' + input_file, 'wb+')
    while 1:
        # Read 128 characters at a time.
        s = data[step * 128:(step + 1) * 128]
        if not s:
            break
        # Encrypt with RSA and append the result to list.
        # RSA encryption returns a tuple containing 1 string, so i fetch the string.
        new_file.write(rsa.encrypt(s.encode('utf8'), generation_of_keys.get_public()))
        step += 1


def encode_file_yield(generation_of_keys, input_file):
    data = open(input_file).read()
    step = 0
    while 1:
        # Read 128 characters at a time.
        s = data[step * 128:(step + 1) * 128]
        if not s:
            break
        # Encrypt with RSA and append the result to list.
        # RSA encryption returns a tuple containing 1 string, so i fetch the string.
        yield rsa.encrypt(s.encode('utf8'), generation_of_keys.get_public())
        step += 1


def decode_file(generation_of_keys, input_file):
    opened_file = open('encoded_' + input_file, mode='rb').read()
    step = 0
    new_file = open('decoded_' + input_file, 'w+')
    while 1:
        s = opened_file[step * 256:(step + 1) * 256]
        if not s:
            break
        to_add = rsa.decrypt(s, generation_of_keys.get_private())
        new_file.write(to_add.decode('utf8'))
        step += 1


def decode_file_yield(generation_of_keys, input_file):
    opened_file = open('encoded_' + input_file, mode='rb').read()
    step = 0
    while 1:
        s = opened_file[step * 256:(step + 1) * 256]
        if not s:
            break
        to_add = rsa.decrypt(s, generation_of_keys.get_private())
        yield to_add.decode('utf8')
        step += 1


def generate_key():
    public, private = rsa.newkeys(2048)
    pu_key = open('publicKey.key', 'wb')
    pu_key.write(public.save_pkcs1('PEM'))
    pu_key.close()
    pr_key = open('privateKey.key', 'wb')
    pr_key.write(private.save_pkcs1('PEM'))
    pr_key.close()


if __name__ == '__main__':
    generate_key()
    with open('privateKey.key', mode='rb') as private_file:
        key_data_private = private_file.read()

    private_key = rsa.PrivateKey.load_pkcs1(key_data_private)

    with open('publicKey.key', mode='rb') as public_file:
        key_data_public = public_file.read()

    public_key = rsa.PublicKey.load_pkcs1(key_data_public)

    GenerationOfKeys = GenerationOfKeys(public_key, private_key)

    encode_file(GenerationOfKeys, "1csv.csv")
    decode_file(GenerationOfKeys, "1csv.csv")
