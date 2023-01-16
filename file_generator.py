import os

HOW_MANY_MB = 100


def create_file(name, size):
    data = "d" * (int(size / 2) - 1)
    arr = bytearray(data, 'utf-16')
    with open(name, 'wb') as f:
        f.write(arr)
    file_size = os.stat(name).st_size
    print("File created of ", file_size / size, " MB size")


create_file("file-name.csv", HOW_MANY_MB * 1024 * 1024)
