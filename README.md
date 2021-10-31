ssh-box: use ssh keys to encrypt files
======================================

work in progress


ssh-box file format
-------------------

A file encrypted by `ssh-box` is an ASCII-armored binary file. The
binary consists of a header followed by the ciphertext.


### ASCII armor

The binary file is base64-encoded and delimited by prefix and suffix
lines. For example,

    -----BEGIN SSH-BOX ENCRYPTED FILE-----
    c3NoLWJveC12MQAAAAABAAAAC3NzaC1lZDI1NTE5AAAAIHRE3hd+N+jMlLuQsnB/IozFl/5O
    4SBvM4uWlCN+Fs8PAAAAAmVnAAAAaKZcNtnpfC0VwHKA2EX/s7zNyuSraWc9xGVmpYJqeKMC
    Py10Oi9sXUN/Q4Kk9aNvbSXVaXQz76Q94cGT89pPx/lD5QusSNxmc8F1PmaGlakDwinczXT7
    JDoDtw/CJDXQ7qdnt/OVDnTRDakxZU+eGgRVMeiwAgkzphgDXFN0IXvW
    -----END SSH-BOX ENCRYPTED FILE-----

### header

The header is encoded in `ssh` style, using data types from [RFC 4251
section 5](https://www.rfc-editor.org/rfc/rfc4251#section-5).

It starts with a nul-terminated string to indicate the file format and
version number, "ssh-box-v1\0".

After the version string is a `uint32` that counts the number of
recipients that can decrypt the file.

Each recipient has four fields:

        string    key type, always "ssh-ed25519"
        string    ssh public key blob
        string    human-readable public key comment
        string    encrypted AEAD nonce and key

(Each line in an OpenSSH authorized keys or public key file contains
the key type in ASCII, followed by a base64-encoded blob, followed by
the comment. The base64 blob has the same contents as the first two
recipient fields above. These two fields frequently occur together in
the SSH protocol.)

The comment is only used when listing an encrypted file's recipients.


### encryption

When encrypting a file, a fresh AEAD nonce and key are generated, and
concatenated into a secret blob without any framing. (They have fixed
sizes determined by the AEAD construction, which is also fixed.)

Each recipient's ssh public key is [converted][to curve25519] using
libsodium `crypto_sign_ed25519_pk_to_curve25519()` and the resulting
key used to encrypt the secret blob using libsodium
[`crypto_box_seal()`][sealed box].


### decryption

When decrypting a file, the header is searched for a recipient whose
key type and public key blob match the user's ssh key.

The user's ssh key pair is [converted][to curve25519] using libsodium
`crypto_sign_ed25519_pk_to_curve25519()` and
`crypto_sign_ed25519_sk_to_curve25519()`, and the resulting key pair
used to decrypt the AEAD secret blob using libsodium
[`crypto_box_seal_open()`][sealed box].


### ciphertext

The file's contents follow immediately after the header. The file is
encrypted using libsodium's [XChaCha20-Poly1305][] AEAD construction,
with the file's contents as the message and the header as the
additional data.


[to curve25519]: https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
[sealed box]: https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes
[XChaCha20-Poly1305]: https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction


todo
----

  * RSA support


licence
-------

> This was written by Tony Finch <<dot@dotat.at>>  
> You may do anything with it. It has no warranty.  
> <https://creativecommons.org/publicdomain/zero/1.0/>  
> SPDX-License-Identifier: CC0-1.0
