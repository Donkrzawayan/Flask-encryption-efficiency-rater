[pyaes](https://github.com/ricmoo/pyaes) with yield
=====

```python
def _feed_stream(feeder, in_stream, block_size = BLOCK_SIZE):
    'Uses feeder to read and convert from in_stream and write to out_stream.'

    while True:
        chunk = in_stream.read(block_size)
        if not chunk:
            break
        converted = feeder.feed(chunk)
        yield converted
    converted = feeder.feed()
    yield converted
```

### Original: [pyaes](https://github.com/ricmoo/pyaes)
