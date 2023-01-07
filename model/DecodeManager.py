from os import path
from pathlib import Path

from flask import send_from_directory, Response, stream_with_context

from model import rsa2048


class DecodeManager:
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
        self.decode_types = {
            'encode_rsa': self._encode_rsa,
            'decode_rsa': self._decode_rsa,
            'decode_rsa_stream': self._decode_rsa_stream
        }

    def caller(self, key, *args):
        return self.decode_types[key](*args)

    def _encode_rsa(self, name, key):
        filename = rsa2048.encode_file(key, path.join(self.upload_folder, name))
        filename = Path(filename).name
        return send_from_directory(self.upload_folder, filename)

    def _decode_rsa(self, name, key):
        filename = rsa2048.decode_file(key, path.join(self.upload_folder, name))
        filename = Path(filename).name
        return send_from_directory(self.upload_folder, filename)

    def _decode_rsa_stream(self, name, key):
        decoded = rsa2048.decode_file_yield(key, path.join(self.upload_folder, name))
        return Response(
            stream_with_context(decoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )
