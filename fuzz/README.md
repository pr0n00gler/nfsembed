# Fuzz targets

The cargo-fuzz package exercises the network-controlled codec, authentication,
record-fragmentation, and authenticated-handle surfaces.

Run bounded smoke sessions locally through the repository's Docker tooling:

```sh
make check
```

The gate covers the generic RPC/XDR, authentication, record, handle, NFSv3
WRITE/READDIR, replay, NFSv4 COMPOUND/callback, attribute/UTF-8/stateid wire
forms, and RPCSEC_GSS token envelopes. CI may invoke the same underlying Cargo
commands directly. Longer corpus and sanitizer runs belong on scheduled
certification runners.
