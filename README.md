# pdf2john

A Rust tool that extracts password hashes from encrypted PDF files for use with [John the Ripper](https://www.openwall.com/john/).

This is a rewrite of the Python [pdf2john](docs/pdf2john.py) script, producing identical output.

## Build

```
cargo build --release
```

## Usage

```
pdf2john [OPTIONS] <PDF_FILES>...
```

### Arguments

- `<PDF_FILES>...` - One or more PDF files to extract hashes from

### Options

- `-s`, `--show-filename` - Prefix output with `filename:` (John the Ripper convention)
- `-h`, `--help` - Print help

### Examples

Extract a hash:

```
$ pdf2john encrypted.pdf
$pdf$2*3*128*-1852*1*16*8c9f0eed2812e81a...
```

Extract with filename prefix (for use with John):

```
$ pdf2john -s encrypted.pdf
encrypted.pdf:$pdf$2*3*128*-1852*1*16*8c9f0eed2812e81a...
```

Process multiple files:

```
$ pdf2john file1.pdf file2.pdf file3.pdf
```

Pipe directly to John the Ripper:

```
$ pdf2john encrypted.pdf > hash.txt
$ john hash.txt
```

## Output Format

```
$pdf$<V>*<R>*<Length>*<P>*<EncryptMetadata>*<id_len>*<id_hex>*<u_len>*<u_hex>*<o_len>*<o_hex>
```

For revision 5/6 PDFs, additional fields are appended:

```
...*<oe_len>*<oe_hex>*<ue_len>*<ue_hex>
```

## Supported Encryption Revisions

| Revision | Scheme         | /U and /O length |
|----------|----------------|------------------|
| 2        | RC4 (basic)    | 32 bytes         |
| 3        | RC4 (extended) | 32 bytes         |
| 4        | RC4 or AES-128 | 32 bytes         |
| 5        | AES-256 (R5)   | 48 bytes         |
| 6        | AES-256        | 48 bytes         |

## Testing

```
cargo test
```

Tests verify output against the reference hash in [docs/example.txt](docs/example.txt) extracted from [docs/example.pdf](docs/example.pdf).

## License

See [LICENSE](LICENSE). Redistribution and use in source and binary forms, with or without modification, are permitted.
