# cosetool

Simple command line utility to interact with CBOR.
Provides generation and validation of CBOR envelopes. Currently only
supports ECDSA/PS256 with SHA256 keys.
Keys can be privded in PEM format, or be generated in memory during
signature generation. For ephemeral keys generated the public key is
stored in the file `public.pem`. Existing files will be overwritten.
When generating a signature, the content type can be set via the `-t`
parameter.

## Examples

### Generate a key pair

```
$ coset -g ecdsa
$ ls
private.pem	public.pem
```

### Sign a message

```
$ coset -s -m "hello world" -t text/plain -k private.pem
$ ls
private.pem	public.pem	sig.cbor
```

### Verify a signature
```
$ coset -f sig.cbor -k public.pem
$ echo $?
0
```

No output is printed on success

### Verify a signature and print body

```
$ coset -f sig.cbor -k public.pem -o text
hello world
```

### Sign a file with an ephemeral key

```
$ dd if=/dev/random bs=512 count=1 of=binary
1+0 records in
1+0 records out
512 bytes transferred in 0.000145 secs (3531034 bytes/sec)
$ coset -s -t application/octet-stream -f binary
$ ls
binary		public.pem	sig.cbor
$ oset -k public.pem -f sig.cbor -o base64
Nx/yRw3R209ufdTr5DAeAI3T8uv/lFgzMdCQM+havVuyYSHeYVonSEe5c1QfVQ3OkSEIlbfZ
V+mXDYggYdDnOWtuy4n1jlGss4QD2fvntCqqNo473QJcgOZBgb/YtMSQkg115i5/ssD7+LWS
pfp/0EMi/vC2mo22sdUSrpDiz1EJ0mQx27AvRgC4y2k69nhIMw9ljr8TDwSMUr/M7/tdSxnd
LBx8pYO6i+8i9w5ayfUpjUjdAzU5m9quTux3X0ftMD3fHpHGjnC0Hu5CdgRUfO9aMiENc6qr
+tw4Khlp711RZ+LFukTriB7r8dYLAlcpRHn6ufrxphf0f73KBYaB2g1UDuAg+sVSWXXQkXk5
NRSKod4TWfuI6H/h6wHQbgWirzTc6gOysUGSavv4z+nM6hUHE/vz7VrG9l7KwE4eKuqZ5vly
7KMPYEiAmFUccESzh2RkGbWvhLlDia23hL1tgCVB9bWILxdEbG766i5lyZcGQVt22w/KwCvA
Y9YMu0u3GLyyA3BBhF/AZz0ZQgQzgnGJ0vj1c5n1gN/kRLW1o26qLri0uYTHpRsdsf+lCemK
/oozuIYULc3XOJhVUV8H5Nv9j5XprbM+ZfWQG+9RNvUZQaLCQ6kpQbgnFF9mdRMTM8ePsl4I
vsqKZNooHIWjGZsO1kZC8kRBJEgPV+67Rd8=
```
