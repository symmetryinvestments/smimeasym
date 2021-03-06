module smimeasym;

import std.stdio;
import std.array : empty;
import std.exception : enforce;
import std.file : exists, isFile;
import std.format : format;
import std.string;

import smimeasym.sslimports;

public import smimeasym.sslimports : X509, EVP_PKEY;

extern(C) {
private:
struct Buffer {
	ubyte* source;
	long len;
}

X509 *load_cert(const char *file);
EVP_PKEY* load_key_from_memory(const char* ptr, int len, const char* password);
EVP_PKEY* load_key(const char* keyfile);
public void freePrivKey(EVP_PKEY* key);
Buffer smime_main_encryption_with_certs(Buffer buf, X509** certs
		, size_t numCerts);
Buffer smime_main_encryption(Buffer buf, char** certs, size_t numCerts);
Buffer smime_main_decryption(Buffer inFile, char* privKeyFilename);
Buffer smime_main_decryption_with_key(Buffer inFile, EVP_PKEY* privKey);
void freeBuffer(Buffer buf);
int lengthErrorsArray();
X509* load_cert_from_memory(const char* d, size_t len);

struct Error {
	int errorCode;
	const char* msg;
}
Error* errorsSmimeHandler();
public void freeCert(X509* certToFree);
}

private ubyte[] copyAnFreeBuffer(Buffer rslt) {
	import std.stdio;
	enforce(rslt.len >= 0, getErrorString(rslt.len));
	ubyte[] ret = new ubyte[](rslt.len);
	foreach(it; 0 .. rslt.len) {
		ret[it] = rslt.source[it];
	}
	freeBuffer(rslt);
	return ret;
}

private string getErrorString(const long errCode) {
	Error* errorArr = errorsSmimeHandler();
	for(int i = 0; i < lengthErrorsArray(); ++i) {
		if(errorArr[i].errorCode == errCode) {
			return fromStringz(errorArr[i].msg).idup;
		}
	}
	return "Unknonw error";
}

X509* loadCert(string filename) {
	enforce(exists(filename), format("Cert '%s' doesn't exist", filename));
	enforce(isFile(filename), format("Cert '%s' is not a file", filename));
	return load_cert(filename.toStringz());
}

X509* loadCertFromString(string data) {
	import std.string : toStringz;
	const(char)* c = toStringz(data);
	return load_cert_from_memory(c, data.length);
}

EVP_PKEY* loadKey(string keyfilename) {
	import std.string : toStringz;
	const(char)* c = toStringz(keyfilename);
	return load_key(c);
}

EVP_PKEY* loadKeyFromString(string data, string password = "") {
	import std.string : toStringz;
	const(char)* c = toStringz(data);
	return load_key_from_memory(c, cast(int)data.length, toStringz(password));
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
	import std.algorithm.searching : all;

	enforce(!certs.empty, "certs array must not be empty");
	enforce(certs.all!(c => c != null), "no cert must be null");
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

ubyte[] smimeDecryptionWithKey(ubyte[] buf, EVP_PKEY* key) {
	Buffer toPass;
	toPass.len = buf.length;
	toPass.source = buf.ptr;

	Buffer rslt = smime_main_decryption_with_key(toPass, key);

	return copyAnFreeBuffer(rslt);
}
