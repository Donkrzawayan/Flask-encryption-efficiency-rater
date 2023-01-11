import time
from os import path
from pathlib import Path

from flask import flash

from model import rsa2048


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
            'decode_aes': self._decode_aes
        }

    def caller(self, key, *args):
        return self.decode_types[key](*args)

    def _encode_rsa(self, name, key):
        start = time.perf_counter()
        filename = rsa2048.encode_file(key, path.join(self.upload_folder, name))
        end = time.perf_counter()
        flash(f'{name} encoding time: {end - start}')
        return Path(filename).name
