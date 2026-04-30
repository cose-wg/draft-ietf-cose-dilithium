
🔥 The code in this repository has not been audited or reviewed.

This code is for generating example spec text, and is likely to be incorrect.

### Generate Examples

```
cd cose
go test

cd jose
go test
```

After regenerating the JSON examples, run `python3 wrap.py` from this
directory to refresh the `*.wrapped.txt` files included by the draft.
Those files are the same content with hard line breaks at 72 columns so
the rendered figures stay within the RFC line-length limit; they are not
valid JSON.

### Credits

- [lamps-wg/dilithium-certificates](https://github.com/lamps-wg/dilithium-certificates/blob/main/examples/generate.go)