import time
from os import path
from pathlib import Path

from flask import flash

from model import rsa2048
from model.pyaes import AESModeOfOperationCTR, Encrypter, Decrypter, PADDING_DEFAULT
from model.pyaes.blockfeeder import BLOCK_SIZE, _feed_stream


class UploadManager:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
        self.decode_types = {
            'encode_rsa': self._encode_rsa,
            'encode_rsa_stream': self._encode_rsa_stream,
            'encode_aes': self._encode_aes,
            'encode_aes_stream': self._encode_aes_stream,
            'decode_rsa': self._decode_rsa,
            'decode_rsa_stream': self._decode_rsa_stream,
            'decode_aes': self._decode_aes,
            'decode_aes_stream': self._decode_aes_stream
        }

    def caller(self, key, *args):
        return self.decode_types[key](*args)

    def _encode_rsa(self, name, key):
        start = time.perf_counter()
        filename = rsa2048.encode_file(key, path.join(self.upload_folder, name))
        end = time.perf_counter()
        flash(f'{name} encoding time: {end - start}')
        return Path(filename).name

    def _encode_rsa_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        encoded_filename = filename.with_stem(f'encoded_{filename.stem}')
        encoded = rsa2048.encode_file_yield(key, filename)
        with open(encoded_filename, 'wb+') as encoded_file:
            for chunk in encoded:
                encoded_file.write(chunk)
        return encoded_filename.name

    def _encode_aes_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        encoded_filename = filename.with_stem(f'encoded_{filename.stem}')
        mode = AESModeOfOperationCTR(key)
        encrypter = Encrypter(mode, padding=PADDING_DEFAULT)
        encoded = _feed_stream(encrypter, open(filename, mode="rb"), BLOCK_SIZE)
        with open(encoded_filename, 'wb+') as encoded_file:
            for chunk in encoded:
                encoded_file.write(chunk)
        return encoded_filename.name

    def _decode_rsa(self, name, key):
        start = time.perf_counter()
        filename = rsa2048.decode_file(key, path.join(self.upload_folder, name))
        end = time.perf_counter()
        flash(f'{name} decoding time: {end - start}')
        return Path(filename).name

    def _encode_aes(self, name, key):
        filename = path.join(self.upload_folder, name)
        data = open(filename).read()
        start = time.perf_counter()
        mode = AESModeOfOperationCTR(key)
        encrypted_data = mode.encrypt(data)
        end = time.perf_counter()
        filename = Path(filename)
        encoded_filename = filename.with_stem(f'encoded_{filename.stem}')
        with open(encoded_filename, 'wb+') as encoded_file:
            encoded_file.write(encrypted_data)
        flash(f'{name} encoding time: {end - start}')
        return encoded_filename.name

    def _decode_aes(self, name, key):
        filename = path.join(self.upload_folder, name)
        data = open(filename, mode="rb").read()
        start = time.perf_counter()
        mode = AESModeOfOperationCTR(bytes(key))
        decrypted_data = mode.decrypt(data)
        end = time.perf_counter()
        filename = Path(filename)
        decoded_filename = filename.with_stem(f'decoded_{filename.stem}')
        with open(decoded_filename, 'wb+') as decoded_file:
            decoded_file.write(decrypted_data)
        flash(f'{name} decoding time: {end - start}')
        return decoded_filename.name

    def _decode_rsa_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        decoded_filename = filename.with_stem(f'decoded_{filename.stem}')
        encoded = rsa2048.decode_file_yield(key, filename)
        with open(decoded_filename, 'wb+') as decoded_file:
            for chunk in encoded:
                decoded_file.write(chunk)
        return decoded_filename.name

    def _decode_aes_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        decoded_filename = filename.with_stem(f'decoded_{filename.stem}')
        mode = AESModeOfOperationCTR(key)
        decrypter = Decrypter(mode, padding=PADDING_DEFAULT)
        decoded = _feed_stream(decrypter, open(filename, mode="rb"), BLOCK_SIZE)
        with open(decoded_filename, 'wb+') as decoded_file:
            for chunk in decoded:
                decoded_file.write(chunk)
        return decoded_filename.name

