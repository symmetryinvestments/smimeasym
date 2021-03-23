module smimeasym;

import std.exception : enforce;
import std.file : exists, isFile;
import std.format : format;
import std.string;

import smimeasym.sslimports;

extern(C) {
private:
struct Buffer {
	ubyte* source;
	long len;
}

X509 *load_cert(const char *file);
Buffer smime_main_encryption_with_certs(Buffer buf, X509** certs
		, size_t numCerts);
Buffer smime_main_encryption(Buffer buf, char** certs, size_t numCerts);
Buffer smime_main_decryption(Buffer inFile, char* privKeyFilename);
void freeBuffer(Buffer buf);
}

private ubyte[] copyAnFreeBuffer(Buffer rslt) {
	ubyte[] ret = new ubyte[](rslt.len);
	foreach(it; 0 .. rslt.len) {
		ret[it] = rslt.source[it];
	}
	freeBuffer(rslt);
	return ret;
}

X509* loadCert(string filename) {
	enforce(exists(filename), format("Cert '%s' doesn't exist", filename));
	enforce(isFile(filename), format("Cert '%s' is not a file", filename));
	return load_cert(filename.toStringz());
}

ubyte[] smimeEncryption(ubyte[] buf, string[] publicKeyFilenames) {
	const(char)*[] asCstrings;
	foreach(key; publicKeyFilenames) {
		enforce(exists(key), format("Cert '%s' doesn't exist", key));
		enforce(isFile(key), format("Cert '%s' is not a file", key));
		asCstrings ~= key.toStringz();
	}

	Buffer toPass;
	toPass.len = buf.length;
	toPass.source = buf.ptr;

	Buffer rslt = smime_main_encryption(toPass, cast(char**)asCstrings.ptr,
			asCstrings.length);
	return copyAnFreeBuffer(rslt);
}

ubyte[] smimeEncryptionWithCerts(ubyte[] buf, X509*[] certs) {
	Buffer toPass;
	toPass.len = buf.length;
	toPass.source = buf.ptr;

	Buffer rslt = smime_main_encryption_with_certs(toPass, certs.ptr,
			certs.length);
	return copyAnFreeBuffer(rslt);
}

ubyte[] smimeDecryption(ubyte[] buf, string privateKeyFilename) {
	enforce(exists(privateKeyFilename)
			, format("Private key '%s' doesn't exist", privateKeyFilename));
	enforce(isFile(privateKeyFilename)
			, format("Private key '%s' is not a file", privateKeyFilename));

	Buffer toPass;
	toPass.len = buf.length;
	toPass.source = buf.ptr;

	Buffer rslt = smime_main_decryption(toPass
			, cast(char*)privateKeyFilename.ptr);

	return copyAnFreeBuffer(rslt);
}
