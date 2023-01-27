import time
from os import path
from pathlib import Path

from flask import flash

from model.Manager import Manager


class UploadManager(Manager):
    def __init__(self, upload_folder):
        super().__init__(upload_folder)

    def caller(self, key, *args):
        return self.encrypt_types[key](*args)

    def _encode_rsa(self, name, key):
        start = time.perf_counter()
        filename = super()._encode_rsa(name, key)
        end = time.perf_counter()
        flash(f'{name} encoding time: {end - start}')
        return filename

    def _encode_rsa_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        encoded_filename = filename.with_stem(f'encoded_{filename.stem}')
        encoded = super()._encode_rsa_stream(name, key)
        with open(encoded_filename, 'wb+') as encoded_file:
            for chunk in encoded:
                encoded_file.write(chunk)
        return encoded_filename.name

    def _encode_aes_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        encoded = super()._encode_aes_stream(name, key)
        encoded_filename = filename.with_stem(f'encoded_{filename.stem}')
        with open(encoded_filename, 'wb+') as encoded_file:
            for chunk in encoded:
                encoded_file.write(chunk)
        return encoded_filename.name

    def _decode_rsa(self, name, key):
        start = time.perf_counter()
        filename = super()._decode_rsa(name, key)
        end = time.perf_counter()
        flash(f'{name} decoding time: {end - start}')
        return filename

    def _encode_aes(self, name, key):
        start = time.perf_counter()
        encoded_filename = super()._encode_aes(name, key)
        end = time.perf_counter()
        flash(f'{name} encoding time: {end - start}')
        return encoded_filename

    def _decode_aes(self, name, key):
        start = time.perf_counter()
        filename = super()._decode_aes(name, key)
        end = time.perf_counter()
        flash(f'{name} decoding time: {end - start}')
        return filename

    def _decode_rsa_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        decoded_filename = filename.with_stem(f'decoded_{filename.stem}')
        encoded = super()._decode_rsa_stream(name, key)
        with open(decoded_filename, 'wb+') as decoded_file:
            for chunk in encoded:
                decoded_file.write(chunk)
        return decoded_filename.name

    def _decode_aes_stream(self, name, key):
        filename = Path(path.join(self.upload_folder, name))
        decoded_filename = filename.with_stem(f'decoded_{filename.stem}')
        decoded = super()._decode_aes_stream(name, key)
        with open(decoded_filename, 'wb+') as decoded_file:
            for chunk in decoded:
                decoded_file.write(chunk)
        return decoded_filename.name
