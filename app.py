import os
import secrets

import rsa
from flask import Flask, render_template, request, flash, redirect, send_from_directory, Response, stream_with_context
from werkzeug.utils import secure_filename

from model import rsa2048

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads/'
if not os.path.exists(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = secrets.token_hex(24)


def _allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/file/<name>')
def uploaded_file(name):
    return render_template('file.html', filename=name)


@app.route('/file/<name>/download')
def download_file(name):
    return send_from_directory(app.config['UPLOAD_FOLDER'], name)


def _decode_rsa(name, key):
    filename = rsa2048.decode_file(key, os.path.join(app.config['UPLOAD_FOLDER'], name))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


decode_types = {
    'rsa': _decode_rsa
}


@app.route('/file/<name>', methods=['POST'])
def decode(name):
    if 'key' not in request.files:
        flash('No file part')
        return redirect(f'/file/{name}')
    key = request.files['key']
    if key.filename == '':
        flash('No selected file')
        return redirect(f'/file/{name}')
    if not key:
        flash('Corrupted file')
        return redirect(f'/file/{name}')
    select = request.form['decode_types']
    return decode_types[select](name, key)


@app.route('/', methods=['GET', 'POST'])
def index():
    upload_folder = app.config['UPLOAD_FOLDER']
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and _allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(upload_folder, filename))
    filenames = [f for f in os.listdir(upload_folder) if os.path.isfile(os.path.join(upload_folder, f))]
    return render_template('uploaded.html', filenames=filenames) if filenames else render_template('index.html')


@app.route('/stream')
def streamed_response():
    filename = 'uploads/Binance_ADAUSDT_d.csv'
    rsa2048.generate_key()
    with open('privateKey.key', mode='rb') as private_file:
        key_data_private = private_file.read()

    private_key = rsa.PrivateKey.load_pkcs1(key_data_private)

    with open('publicKey.key', mode='rb') as public_file:
        key_data_public = public_file.read()

    public_key = rsa.PublicKey.load_pkcs1(key_data_public)

    generationOfKeys = rsa2048.GenerationOfKeys(public_key, private_key)

    decoded = rsa2048.encode_file_yield(generationOfKeys, filename)
    # decoded = rsa2048.decode_file_yield(generationOfKeys, filename)
    return Response(
        stream_with_context(decoded),
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )


if __name__ == '__main__':
    app.run(debug=True)
