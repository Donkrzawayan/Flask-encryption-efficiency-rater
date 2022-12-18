from os import path
from pathlib import Path

from flask import send_from_directory

from model import rsa2048


class DecodeManager:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
        self.decode_types = {
            'rsa': self._decode_rsa
        }

    def caller(self, key, *args):
        return self.decode_types[key](*args)

    def _decode_rsa(self, name, key):
        filename = rsa2048.decode_file(key, path.join(self.upload_folder, name))
        filename = Path(filename).name
        return send_from_directory(self.upload_folder, filename)