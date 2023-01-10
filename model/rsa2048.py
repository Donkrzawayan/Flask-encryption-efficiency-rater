import io
from pathlib import Path
from zipfile import ZipFile

import rsa


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
    public_key = rsa.PublicKey.load_pkcs1(public_key.read())
    data = open(input_file).read()
    step = 0
    while True:
        # Read 128 characters at a time.
        s = data[step * 128:(step + 1) * 128]
        if not s:
            break
        # Encrypt with RSA and append the result to list.
        # RSA encryption returns a tuple containing 1 string, so i fetch the string.
        yield rsa.encrypt(s.encode('utf8'), public_key)
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
    data = open(input_file, mode='rb').read()
    step = 0
    while True:
        s = data[step * 256:(step + 1) * 256]
        if not s:
            break
        to_add = rsa.decrypt(s, private_key)
        yield to_add.decode('utf8')
        step += 1


def generate_keys():
    public, private = rsa.newkeys(2048)
    data = io.BytesIO()
    with ZipFile(data, mode='w') as z:
        z.writestr('public.key', public.save_pkcs1('PEM').decode('utf8'))
        z.writestr('private.key', private.save_pkcs1('PEM').decode('utf8'))
    data.seek(0)
    return data
