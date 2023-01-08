from pathlib import Path

import rsa as rsa


def encode_file(public_key, input_file):
    public_key = rsa.PublicKey.load_pkcs1(public_key.read())
    path = Path(input_file)
    encoded_filename = path.with_stem(f'encoded_{path.stem}')
    data = open(input_file).read()
    step = 0
    with open(encoded_filename, 'wb+') as encoded_file:
        while True:
            # Read 128 characters at a time.
            s = data[step * 128:(step + 1) * 128]
            if not s:
                break
            # Encrypt with RSA and append the result to list.
            # RSA encryption returns a tuple containing 1 string, so i fetch the string.
            encoded_file.write(rsa.encrypt(s.encode('utf8'), public_key))
            step += 1

    return encoded_file.name


def encode_file_yield(public_key, input_file):
    data = open(input_file).read()
    step = 0
    while 1:
        # Read 128 characters at a time.
        s = data[step * 128:(step + 1) * 128]
        if not s:
            break
        # Encrypt with RSA and append the result to list.
        # RSA encryption returns a tuple containing 1 string, so i fetch the string.
        yield rsa.encrypt(s.encode('utf8'), public_key)
        step += 1


def decode_file1(private_key, input_file):
    opened_file = open('encoded_' + input_file, mode='rb').read()
    step = 0
    new_file = open('decoded_' + input_file, 'w+')
    while 1:
        s = opened_file[step * 256:(step + 1) * 256]
        if not s:
            break
        to_add = rsa.decrypt(s, private_key)
        new_file.write(to_add.decode('utf8'))
        step += 1


def decode_file(private_key, input_file):
    private_key = rsa.PrivateKey.load_pkcs1(private_key.read())
    path = Path(input_file)
    decoded_filename = path.with_stem(f'decoded_{path.stem}')
    data = open(input_file, mode='rb').read()
    step = 0
    with open(decoded_filename, 'w+') as decoded_file:
        while True:
            s = data[step * 256:(step + 1) * 256]
            if not s:
                break
            to_add = rsa.decrypt(s, private_key)
            decoded_file.write(to_add.decode('utf8'))
            step += 1

    return decoded_file.name


def decode_file_yield(private_key, input_file):
    private_key = rsa.PrivateKey.load_pkcs1(private_key.read())
    opened_file = open(input_file, mode='rb').read()
    step = 0
    while 1:
        s = opened_file[step * 256:(step + 1) * 256]
        if not s:
            break
        to_add = rsa.decrypt(s, private_key)
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

    encode_file(public_key, "1csv.csv")
    decode_file1(private_key, "1csv.csv")
