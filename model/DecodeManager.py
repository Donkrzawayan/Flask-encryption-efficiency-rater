import time
from os import path
from pathlib import Path

import rsa
from flask import send_from_directory, Response, stream_with_context, flash

from model import rsa2048, aes


class DecodeManager:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
        self.decode_types = {
            'encode_rsa': self._encode_rsa,
            'encode_rsa_stream': self._encode_rsa_stream,
            'encode_aes': self._encode_aes,
            'decode_rsa': self._decode_rsa,
            'decode_rsa_stream': self._decode_rsa_stream,
            'decode_aes': self._decode_aes
        }

    def caller(self, key, *args):
        return self.decode_types[key](*args)

    def _encode_rsa(self, name, key):
        start = time.perf_counter()
        filename = rsa2048.encode_file(key, path.join(self.upload_folder, name))
        end = time.perf_counter()
        filename = Path(filename).name
        flash(f'{name} encoding time: {end - start}')
        return send_from_directory(self.upload_folder, filename)

    def _encode_rsa_stream(self, name, key):
        encoded = rsa2048.encode_file_yield(key, path.join(self.upload_folder, name))
        return Response(
            stream_with_context(encoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )

    def _encode_aes(self, name, key):
        key = str(rsa.PublicKey.load_pkcs1(key.read()))
        filename = path.join(self.upload_folder, name)
        data = open(filename).read()
        cipher = aes.AESCipher(key)
        start = time.perf_counter()
        encrypted_data = cipher.encrypt(data)
        end = time.perf_counter()
        filename = Path(filename)
        encoded_filename = filename.with_stem(f'encoded_{filename.stem}')
        with open(encoded_filename, 'wb+') as encoded_file:
            encoded_file.write(bytes(encrypted_data, 'utf-8'))
        flash(f'{name} encoding time: {end - start}')
        return send_from_directory(self.upload_folder, encoded_filename.name)

    def _decode_aes(self, name, key):
        key = str(rsa.PublicKey.load_pkcs1(key.read()))
        filename = path.join(self.upload_folder, name)
        data = open(filename, encoding='utf-8').read()
        cipher = aes.AESCipher(key)
        start = time.perf_counter()
        decrypted_data = cipher.decrypt(data)
        end = time.perf_counter()
        filename = Path(filename)
        decoded_filename = filename.with_stem(f'decoded_{filename.stem}')
        with open(decoded_filename, 'wb+') as decoded_file:
            decoded_file.write(bytes(decrypted_data, 'utf-8'))
        flash(f'{name} decoding time: {end - start}')
        return send_from_directory(self.upload_folder, decoded_filename.name)

    def _decode_rsa(self, name, key):
        start = time.perf_counter()
        filename = rsa2048.decode_file(key, path.join(self.upload_folder, name))
        end = time.perf_counter()
        filename = Path(filename).name
        flash(f'{name} decoding time: {end - start}')
        return send_from_directory(self.upload_folder, filename)

    def _decode_rsa_stream(self, name, key):
        decoded = rsa2048.decode_file_yield(key, path.join(self.upload_folder, name))
        return Response(
            stream_with_context(decoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )
