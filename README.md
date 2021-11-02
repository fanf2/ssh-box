ssh-box: use ssh keys to encrypt files
======================================

work in progress


caveat: poor key hygiene
------------------------

It is generally considered to be a bad idea to use the same key pair
for signing and encryption. SSH key pairs are normally used for
signing (i.e for authentication), but `ssh-box` repurposes them as
encryption keys.

The risk with this kind of reuse is that it opens you up to
cross-protocol attacks, where one protocol is used to gain access to a
signing or encryption oracle that allows you to break the other
protocol.

Another tool that re-uses ssh keys for encryption is [`age`][]. The
https://age-encryption.org/v1 format specification argues that it is
actually safe, for `age`'s tweaked curve25519 scheme. You can also use
RSA keys with `age`, but its spec doesn't explain why this use of RSA
is safe.

The cryptographic constructions used by `age` and `ssh-box` are fairly
similar, although `ssh-box` mostly uses vanilla libsodium
constructions, whereas `age` is more cryptographically sophisticated.


### keeping clean

To avoid this risk, you can use `ssh-box -g` to generate a key
specifically for encryption. Its filename is `~/.ssh/box_ed25519`
which is not one of the standard ssh authentication keys.



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

Each recipient has three fields:

        string    ssh public key
        string    human-readable public key comment
        string    encrypted AEAD nonce and key

An SSH public key consists of:

        string    key type
		... remaining fields depend on the type ...

(Each line in an OpenSSH authorized keys or public key file contains
the key type in ASCII, followed by a base64-encoded blob, followed by
the comment. The decoded base64 blob has the same contents as the
recipient's ssh public key field. This form of public key occurs
frequently in the SSH protocol.)

The comment is only used when listing an encrypted file's recipients.
If the comment consists of a single nul byte then it should be omitted
from the list.


### agility

In the future, this `ssh-box` file format may support other public key
types. Tools that read `ssh-box` encrypted files should not raise an
error when they see an unrecognised recipient key type.

The version string at the start of the file determines the bulk
encryption scheme, and the mapping from ssh key types to asymmetric
encryption schemes.


### encryption

When encrypting a file, a fresh AEAD nonce and key are generated, and
concatenated into a secret blob without any framing. (They have fixed
sizes determined by the AEAD construction.)

Each ssh-ed25519 recipient public key is converted using libsodium
[`crypto_sign_ed25519_pk_to_curve25519()`][to curve25519] and the
resulting key is used to encrypt the secret blob using libsodium
[`crypto_box_seal()`][sealed box].

Each ssh-rsa recipient public key is used to encrypt the secret blob
using RSA-OAEP [RFC 8017][] with SHA-256 and MGF1 and the label
"ssh-box-v1-rsa-oaep".


### decryption

When decrypting a file, the header is searched for a recipient whose
key type and public key blob match the user's ssh key.

The user's ssh-ed25519 key pair is converted using libsodium
[`crypto_sign_ed25519_pk_to_curve25519()` and
`crypto_sign_ed25519_sk_to_curve25519()`][to curve25519], and the
resulting key pair is used to decrypt the AEAD secret blob using
libsodium [`crypto_box_seal_open()`][sealed box].

Or if the user's private key is ssh-rsa, it is used to decrypt the
secret blob with RSA-OAEPas described above.


### ciphertext

The file's contents follow immediately after the header. The file is
encrypted using libsodium's [XChaCha20-Poly1305][] AEAD construction,
with the file's contents as the message and the header as the
additional data.


[to curve25519]: https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
[sealed box]: https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes
[XChaCha20-Poly1305]: https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
[RFC 8017]: https://www.rfc-editor.org/rfc/rfc8017

licence
-------

> This was written by Tony Finch <<dot@dotat.at>>  
> You may do anything with it. It has no warranty.  
> <https://creativecommons.org/publicdomain/zero/1.0/>  
> SPDX-License-Identifier: CC0-1.0
