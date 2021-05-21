// So the problem to solve is that I needed a function
// that encrypts an array of ubytes with multiple public
// keys. The resulting, encrypted, array of bytes, when saved
// to a file, should be decrypted-able by any private key
// matching any of the used public key.
// This should be possible with the openssl cli.
// smime is used as bundle everything together, properly
// not the best approach, but hey it works.
// The asymmetrically keys are used to encrypt a symmetry
// AES256 key that is in turn used to encrypt the array of
// bytes.
//
// The following three functions is where the work happens
//
// Buffer smime_main_decryption(Buffer inFile, char* certFile);
// Buffer smime_main_encryption(Buffer buf, char** certs, size_t numCerts);
// Buffer smime_main_encryption_with_certs(Buffer buf, X509** certs, size_t numCerts);
//
// # Example:
//
// ## Build the test key pairs
// openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -subj "/C=US/ST=*/L=*/O=*/OU=*/CN=Alice/" -keyout alice.key -out alice.pub
// openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -subj "/C=US/ST=*/L=*/O=*/OU=*/CN=Bob/" -keyout bob.key -out bob.pub
// openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -subj "/C=US/ST=*/L=*/O=*/OU=*/CN=Frank/" -keyout frank.key -out frank.pub
//
// ## Create the secret message
// echo 'All our secretz are belong to us' > secrets.txt
//
// ## Compile the program
// gcc -Wall -ggdb smime.c -o smime -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto
//
// ## Encrypt secrets.txt into secrets.txt.enc
// ./smime enc
//
// you should see a new file secrets.txt.enc
//
// ## Decrypt secrets.txt.enc with openssl
//
// openssl smime -decrypt -in secrets.txt.enc -inform PEM -inkey bob.key
//
// ## The compiled program can also decrypt
//
// ./smime 0
//
// this should use the first private key listed in function main to decrypt secrets.txt.enc
// the decrypted text is saved in file secrets_new.txt
//
// To see the usage have a look at the main function

#include <stdio.h>
#include <string.h>
//#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>


#define SMIME_OP 0x10
#define SMIME_SIGNERS 0x40
#define SMIME_ENCRYPT (1 | SMIME_OP)

# define B_FORMAT_TEXT 0x8000
# define FORMAT_ASN1 4					  /* ASN.1/DER */
//# define FORMAT_PEM (5 | B_FORMAT_TEXT)
# define FORMAT_PEM (5 | B_FORMAT_TEXT)
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_PKCS12 6
# define FORMAT_SMIME (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE 8					  /* Not really a file format */
# define FORMAT_MSBLOB 11					 /* MS Key blob format */
# define FORMAT_PVK	12					 /* MS PVK file format */

BIO *bio_err;

EVP_PKEY *load_key(const char *file);
EVP_PKEY *load_key_impl(const char *file, int format, int maybe_stdin
	, const char *pass, ENGINE *e, const char *key_descrip);

typedef struct BufferImpl {
	unsigned char* source;
	long len;
} Buffer;

static Buffer smime_main_encryptionImpl(Buffer buf, STACK_OF(X509) *encerts);
Buffer smime_main_encryption_with_certs(Buffer buf, X509** certs, size_t numCerts);

static int istext(int format) {
	return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

static const char *modestr(char mode, int format) {
	OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

	switch (mode) {
	case 'a':
		return istext(format) ? "a" : "ab";
	case 'r':
		return istext(format) ? "r" : "rb";
	case 'w':
		return istext(format) ? "w" : "wb";
	}
	/* The assert above should make sure we never reach this point */
	return NULL;
}

static int pass_cb(char* a, int b, int c, void* d) {
	return -1;
}

static int load_pkcs12(BIO *in, const char *desc
	, pem_password_cb * unused, void * unused2, EVP_PKEY **pkey, X509 **cert
	, STACK_OF(X509) **ca)
{
	const char *pass;
	PKCS12 *p12 = d2i_PKCS12_bio(in, NULL);
	int ret = -1;
	if(p12 == NULL) {
		goto die;
	}
	/* See if an empty password will do */
	if(PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0)) {
		pass = "";
	}
	ret = PKCS12_parse(p12, pass, pkey, cert, ca);
 die:
	PKCS12_free(p12);
	return ret;
}

typedef struct pw_cb_data {
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

void freeBuffer(Buffer buf) {
	if(buf.len > 0 && buf.source != NULL) {
		free(buf.source);
	}
}

void freeCert(X509* certToFree) {
	if(certToFree != NULL) {
		X509_free(certToFree);
	}
}

void freePrivKey(EVP_PKEY* key) {
	EVP_PKEY_free(key);
}

EVP_PKEY* load_key(const char* keyfile) {
	int keyform = FORMAT_PEM;
	char *passin = NULL;
	ENGINE *e = NULL;
	EVP_PKEY* key = load_key_impl(keyfile, keyform, 0, passin, e, "signing key file");
	return key;
}

EVP_PKEY* load_key_from_memory(const char* ptr, int len, const char* password) {
	BIO* in = BIO_new(BIO_s_mem());
	if(in == NULL) {
		return NULL;
	}
	BIO_write(in, ptr, (int)len);

	PW_CB_DATA cb_data;
	cb_data.password = password;
	//cb_data.prompt_info = file;

	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(in, NULL, pass_cb, &cb_data);
	BIO_free(in);
	return pkey;
}

EVP_PKEY* load_key_impl(const char *file, int format, int maybe_stdin
	, const char *pass, ENGINE *e, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if(file == NULL && (!maybe_stdin || format == FORMAT_ENGINE)) {
		goto end;
	}
	if(format == FORMAT_ENGINE) {
		if(e != NULL) {
			FILE *f = fopen("key.pem", "rb");
			PEM_read_PrivateKey(f, &pkey, NULL, NULL);
			fclose(f);
			if(pkey == NULL) {
				goto end;
			}
		}
		goto end;
	}
	key = BIO_new_file(file, modestr('r', format));
	if(key == NULL) {
		goto end;
	}
	if(format == FORMAT_ASN1) {
		pkey = d2i_PrivateKey_bio(key, NULL);
	} else if(format == FORMAT_PEM) {
		pkey = PEM_read_bio_PrivateKey(key, NULL,
									   pass_cb,
									   &cb_data);
	} else if(format == FORMAT_PKCS12) {
		if(!load_pkcs12(key, key_descrip,
						 pass_cb, &cb_data,
						 &pkey, NULL, NULL))
		{
			goto end;
		}
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA) && !defined (OPENSSL_NO_RC4)
	} else if(format == FORMAT_MSBLOB) {
		pkey = b2i_PrivateKey_bio(key);
	} else if(format == FORMAT_PVK) {
		pkey = b2i_PVK_bio(key, pass_cb, &cb_data);
#endif
	} else {
		goto end;
	}
 end:
	BIO_free(key);
	return pkey;
}

static BIO *bio_open_default_(const char *filename, char mode, int format
	, int quiet)
{
	BIO *ret = BIO_new_file(filename, modestr(mode, format));
	if(quiet) {
		ERR_clear_error();
		return ret;
	}
	if(ret != NULL) {
		return ret;
	}
	return NULL;
}

static BIO *bio_open_default(const char *filename, char mode, int format) {
	return bio_open_default_(filename, mode, format, 0);
}

static X509 *load_certImpl(const char *file, int format
	, const char *cert_descrip)
{
	X509 *x = NULL;
	BIO *cert = bio_open_default(file, 'r', format);
	if(cert == NULL) {
		goto end;
	}

	if(format == FORMAT_ASN1) {
		x = d2i_X509_bio(cert, NULL);
	} else if(format == FORMAT_PEM) {
		x = PEM_read_bio_X509_AUX(cert, NULL, 0, NULL);
	} else if(format == FORMAT_PKCS12) {
		if(!load_pkcs12(cert, cert_descrip, NULL, NULL, NULL, &x, NULL)) {
			goto end;
		}
	} else {
		goto end;
	}
 end:
	if(x == NULL) {
		// I wish there were Exceptions in C
	}
	BIO_free(cert);
	return x;
}

X509 *load_cert_from_memory(const char* d, size_t len) {
	BIO* in = BIO_new(BIO_s_mem());
	if(in == NULL) {
		return NULL;
	}
	BIO_write(in, d, (int)len);
	X509* x = PEM_read_bio_X509_AUX(in, NULL, 0, NULL);
	BIO_free(in);
	return x;
}

X509 *load_cert(const char *file) {
	return load_certImpl(file, FORMAT_PEM, "recipient certificate file");
}

Buffer smime_main_encryption(Buffer buf
	, char** certs, size_t numCerts)
{
	// The public keys/certs are the leftover arguments
	// now we pass them in as certs
	Buffer ret;
	ret.len = -1;
	X509 **certsLoaded = (X509**)malloc(sizeof(X509*) * numCerts);
	for(size_t i = 0; i < numCerts; ++i) {
		X509* tmp = load_cert(certs[i]);
		if(tmp == NULL) {
			ret.len = -4;
			goto end;
		}
		certsLoaded[i] = tmp;
	}

	ret = smime_main_encryption_with_certs(buf, certsLoaded, numCerts);
end:
	free(certsLoaded);
	return ret;
}

Buffer smime_main_encryption_with_certs(Buffer buf, X509** certs
	, size_t numCerts)
{
	STACK_OF(X509) *encerts = sk_X509_new_null();

	Buffer ret;
	ret.len = -1;

	if(encerts == NULL) {
		goto end;
	}
	for(size_t i = 0; i < numCerts; ++i) {
		sk_X509_push(encerts, certs[i]);
	}

	ret = smime_main_encryptionImpl(buf, encerts);
	sk_X509_pop_free(encerts, X509_free);
end:
	return ret;
}

typedef struct ErrorImpl {
	int errorCode;
	const char* msg;
} Error;

#define ERRORARRAYLENGTH 12

int lengthErrorsArray() {
	return ERRORARRAYLENGTH;
}

Error __errorsSmimeHandler[ERRORARRAYLENGTH] =
	{ {  -1, "X509 verify param new failed" }
	, {  -2, "Multiple signers or keys not allowed" }
	, {  -3, "Cipher must not be NULL" }
	, {  -4, "Failed to load key" }
	, {  -5, "Failed to create input data source" }
	, {  -6, "Failed to create output data destination" }
	, {  -7, "Failed to create PKCS#7 structure" }
	, {  -8, "Error writing output" }
	, {  -9, "No recipient certificate or key specified" }
	, { -10, "Failed to load private key" }
	, { -11, "Error reading S/MIME message" }
	, { -12, "Error decrypting PKCS#7 structure" }
	};

Error* errorsSmimeHandler() {
	return __errorsSmimeHandler;
}

Buffer smime_main_encryptionImpl(Buffer buf, STACK_OF(X509) *encerts) {
	BIO *in = NULL;
	BIO *out = NULL;
	BIO *indata = NULL;
	EVP_PKEY *key = NULL;
	PKCS7 *p7 = NULL;
	STACK_OF(OPENSSL_STRING) *sksigners = NULL;
	STACK_OF(OPENSSL_STRING) *skkeys = NULL;
	STACK_OF(X509) *other = NULL;
	X509 *recip = NULL;
	X509 *signer = NULL;
	X509_STORE *store = NULL;
	X509_VERIFY_PARAM *vpm = NULL;
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	char *keyfile = NULL;
	char *passin = NULL;
	//int flags = PKCS7_DETACHED | PKCS7_BINARY | PKCS7_TEXT;
	int flags = PKCS7_BINARY;
	int keyform = FORMAT_PEM;
	int rv = 0;
	ENGINE *e = NULL;

	int operation = SMIME_ENCRYPT;

	Buffer ret;
	ret.len = 0;

	if((vpm = X509_VERIFY_PARAM_new()) == NULL) {
		ret.len = -1;
		return ret;
	}

	if(!(operation & SMIME_SIGNERS) && (skkeys != NULL || sksigners != NULL)) {
		ret.len = -2;
		goto end;
	}

	if(cipher == NULL) {
		ret.len = -3;
		goto end;
	}

	keyfile = NULL;

	if(keyfile != NULL) {
		key = load_key_impl(keyfile, keyform, 0, passin, e, "signing key file");
		if(key == NULL) {
			ret.len = -4;
			goto end;
		}
	}

	in = BIO_new(BIO_s_mem());
	if(in == NULL) {
		ret.len = -5;
		goto end;
	}
	BIO_write(in, buf.source, (int)buf.len);

	out = BIO_new(BIO_s_mem());
	if(out == NULL) {
		ret.len = -6;
		goto end;
	}

	p7 = PKCS7_encrypt(encerts, in, cipher, flags);

	if(p7 == NULL) {
		ret.len = -7;
		goto end;
	}

	rv = PEM_write_bio_PKCS7_stream(out, p7, in, flags);
	if(rv == 0) {
		ret.len = -8;
		goto end;
	}

	char* data;
	ret.len = BIO_get_mem_data(out, &data);
	ret.source = (unsigned char*)malloc(ret.len);
	BIO_read(out, ret.source, ret.len);

 end:
	if(ret.len)
		ERR_print_errors(bio_err);
	sk_X509_pop_free(other, X509_free);
	X509_VERIFY_PARAM_free(vpm);
	sk_OPENSSL_STRING_free(sksigners);
	sk_OPENSSL_STRING_free(skkeys);
	X509_STORE_free(store);
	X509_free(recip);
	X509_free(signer);
	EVP_PKEY_free(key);
	PKCS7_free(p7);
	OPENSSL_free(e);
	BIO_free(in);
	BIO_free(out);
	BIO_free(indata);
	OPENSSL_free(passin);
	return ret;
}

Buffer smime_main_decryption_with_key(Buffer inFile, EVP_PKEY* privKey) {
	BIO *in = NULL;
	BIO *out = NULL;
	BIO *indata = NULL;
	PKCS7 *p7 = NULL;
	X509 *recip = NULL;
	X509_VERIFY_PARAM *vpm = NULL;
	int flags = PKCS7_BINARY;
	//int informat = FORMAT_PEM;
	int informat = FORMAT_PEM;

	Buffer ret;
	ret.len = -1;

	if((vpm = X509_VERIFY_PARAM_new()) == NULL) {
		ret.len = -1;
		goto end;
	}

	if(privKey == NULL) {
		ret.len = -10;
		goto end;
	}

	in = BIO_new(BIO_s_mem());
	if(in == NULL) {
		ret.len = -5;
		goto end;
	}
	BIO_write(in, inFile.source, (int)inFile.len);

	if(informat == FORMAT_SMIME) {
		p7 = SMIME_read_PKCS7(in, &indata);
	} else if(informat == FORMAT_PEM) {
		p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	}

	if(p7 == NULL) {
		ret.len = -11;
		goto end;
	}
	out = BIO_new(BIO_s_mem());
	if(out == NULL) {
		ret.len = -6;
		goto end;
	}

	if(PKCS7_decrypt(p7, privKey, recip, out, flags) == 0) {
		ret.len = -12;
		goto end;
	}

	ret.len = 0;

	char* data;
	ret.len = BIO_get_mem_data(out, &data);
	ret.source = (unsigned char*)malloc(ret.len);
	BIO_read(out, ret.source, ret.len);

 end:
	if(ret.len) {
		ERR_print_errors(bio_err);
	}
	X509_VERIFY_PARAM_free(vpm);
	X509_free(recip);
	PKCS7_free(p7);
	BIO_free(in);
	BIO_free(indata);
	BIO_free_all(out);
	return ret;
}

Buffer smime_main_decryption(Buffer inFile, const char* privKeyFilename) {
	BIO *in = NULL;
	BIO *out = NULL;
	BIO *indata = NULL;
	EVP_PKEY *key = NULL;
	PKCS7 *p7 = NULL;
	STACK_OF(OPENSSL_STRING) *sksigners = NULL;
	STACK_OF(OPENSSL_STRING) *skkeys = NULL;
	STACK_OF(X509) *other = NULL;
	X509 *cert = NULL;
	X509 *recip = NULL;
	X509 *signer = NULL;
	X509_STORE *store = NULL;
	X509_VERIFY_PARAM *vpm = NULL;
	const char *keyfile = privKeyFilename;
	char *passin = NULL;
	int flags = PKCS7_BINARY;
	//int informat = FORMAT_PEM;
	int informat = FORMAT_PEM;
	int keyform = FORMAT_PEM;
	ENGINE *e = NULL;

	Buffer ret;
	ret.len = -1;

	if((vpm = X509_VERIFY_PARAM_new()) == NULL) {
		ret.len = -1;
		goto end;
	}

	if(keyfile == NULL) {
		ret.len = -9;
		goto end;
	}

	key = load_key_impl(keyfile, keyform, 0, passin, e, "signing key file");
	if(key == NULL) {
		ret.len = -10;
		goto end;
	}

	in = BIO_new(BIO_s_mem());
	if(in == NULL) {
		ret.len = -5;
		goto end;
	}
	BIO_write(in, inFile.source, (int)inFile.len);

	if(informat == FORMAT_SMIME) {
		p7 = SMIME_read_PKCS7(in, &indata);
	} else if(informat == FORMAT_PEM) {
		p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	}

	if(p7 == NULL) {
		ret.len = -11;
		goto end;
	}
	out = BIO_new(BIO_s_mem());
	if(out == NULL) {
		ret.len = -6;
		goto end;
	}

	if(PKCS7_decrypt(p7, key, recip, out, flags) == 0) {
		ret.len = -12;
		goto end;
	}

	ret.len = 0;

	char* data;
	ret.len = BIO_get_mem_data(out, &data);
	ret.source = (unsigned char*)malloc(ret.len);
	BIO_read(out, ret.source, ret.len);

 end:
	if(ret.len) {
		ERR_print_errors(bio_err);
	}
	sk_X509_pop_free(other, X509_free);
	X509_VERIFY_PARAM_free(vpm);
	sk_OPENSSL_STRING_free(sksigners);
	sk_OPENSSL_STRING_free(skkeys);
	X509_STORE_free(store);
	X509_free(cert);
	X509_free(recip);
	X509_free(signer);
	EVP_PKEY_free(key);
	PKCS7_free(p7);
	OPENSSL_free(e);
	BIO_free(in);
	BIO_free(indata);
	BIO_free_all(out);
	OPENSSL_free(passin);
	return ret;
}
