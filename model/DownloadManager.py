import time

from flask import send_from_directory, Response, stream_with_context, flash

from model.Manager import Manager


class DownloadManager(Manager):
    def __init__(self, upload_folder):
        super().__init__(upload_folder)

    def caller(self, key, *args):
        return self.encrypt_types[key](*args)

    def _encode_rsa(self, name, key):
        start = time.perf_counter()
        filename = super()._encode_rsa(name, key)
        end = time.perf_counter()
        flash(f'{name} encoding time: {end - start}')
        return send_from_directory(self.upload_folder, filename)

    def _encode_rsa_stream(self, name, key):
        encoded = super()._encode_rsa_stream(name, key)
        return Response(
            stream_with_context(encoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )

    def _encode_aes_stream(self, name, key):
        encoded = super()._encode_aes_stream(name, key)
        return Response(
            stream_with_context(encoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )

    def _encode_aes(self, name, key):
        start = time.perf_counter()
        encoded_filename = super()._encode_aes(name, key)
        end = time.perf_counter()
        flash(f'{name} encoding time: {end - start}')
        return send_from_directory(self.upload_folder, encoded_filename)

    def _decode_aes(self, name, key):
        start = time.perf_counter()
        filename = super()._decode_aes(name, key)
        end = time.perf_counter()
        flash(f'{name} decoding time: {end - start}')
        return send_from_directory(self.upload_folder, filename)

    def _decode_rsa(self, name, key):
        start = time.perf_counter()
        filename = super()._decode_rsa(name, key)
        end = time.perf_counter()
        flash(f'{name} decoding time: {end - start}')
        return send_from_directory(self.upload_folder, filename)

    def _decode_rsa_stream(self, name, key):
        decoded = super()._decode_rsa_stream(name, key)
        return Response(
            stream_with_context(decoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )

    def _decode_aes_stream(self, name, key):
        decoded = super()._decode_aes_stream(name, key)
        return Response(
            stream_with_context(decoded),
            headers={
                'Content-Disposition': f'attachment; filename={name}'
            }
        )
