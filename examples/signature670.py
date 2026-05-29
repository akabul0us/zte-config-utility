#!/usr/bin/env python3
import zcu
with open('config.bin', 'rb') as f:
    zcu.zte.read_header(f, little_endian=True)
    sig = zcu.zte.read_signature(f)
    print(sig.decode())
# F670L
