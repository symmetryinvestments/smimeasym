# smimeasym S/MIME asymmetrical encryption

![CI](https://github.com/symmetryinvestments/smimeasym/workflows/ci/badge.svg)

So the problem to solve is that I needed a function
that encrypts an array of ubytes with multiple public
keys.
The resulting, encrypted, array of bytes, when saved
to a file, should be decrypted-able by any private key
matching any of the used public key.
This should be possible with the openssl cli.

## Usage

Key pair suitable
```sh
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -subj "/C=US/ST=*/L=*/O=*/OU=*/CN=Frank/" -keyout frank.key -out frank.pub
```

There are two main functions

```D
ubyte[] smimeEncryption(ubyte[] buf, string[] publicKeyFilenames);

ubyte[] smimeDecryption(ubyte[] buf, string privateKeyFilename);

X509* loadCert(string filename);
X509* loadCertFromString(string theCert);
void freeCert(X509* certToFree);

ubyte[] smimeEncryptionWithCerts(ubyte[] buf, X509*[] certs);
EVP_PKEY* loadKeyFromString(string data, string password = "");
ubyte[] smimeDecryptionWithKey(ubyte[] buf, EVP_PKEY* key);
```

The opencli should be able to decrypt created files from the data from
smimeEncryption with the following shell command

```sh
openssl smime -decrypt -in secrets.txt.enc -inform PEM -inkey bob.key
```

## Tests

The password for the private key frank_with_pass.key is **foobar**.
