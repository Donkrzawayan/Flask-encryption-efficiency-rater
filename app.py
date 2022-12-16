import os
import secrets
import time
from os import listdir

import rsa
from flask import Flask, render_template, request, flash, redirect, send_from_directory, Response, stream_with_context
from werkzeug.utils import secure_filename

from model.rsa2048 import generate_key, GenerationOfKeys, encode_file_yield, decode_file_yield, encode_file

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads/'
if not os.path.exists(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = secrets.token_hex(24)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<name>')
def download_file(name):
    start = time.time()
    result = send_from_directory(app.config['UPLOAD_FOLDER'], name)
    end = time.time()
    print("Download time: ", end - start)
    # dodac czas szyfrowania
    return result


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
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(upload_folder, filename))
    filenames = [f for f in listdir(upload_folder) if os.path.isfile(os.path.join(upload_folder, f))]
    return render_template('uploaded.html', filenames=filenames) if filenames else render_template('index.html')


@app.route('/stream')
def streamed_response():
    filename = "a.csv"
    generate_key()
    with open('privateKey.key', mode='rb') as private_file:
        key_data_private = private_file.read()

    private_key = rsa.PrivateKey.load_pkcs1(key_data_private)

    with open('publicKey.key', mode='rb') as public_file:
        key_data_public = public_file.read()

    public_key = rsa.PublicKey.load_pkcs1(key_data_public)

    generationOfKeys = GenerationOfKeys(public_key, private_key)

    encode_file(generationOfKeys, filename)
    decoded = decode_file_yield(generationOfKeys, filename)
    return Response(
        stream_with_context(decoded),
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )


if __name__ == '__main__':
    app.run(debug=True)
