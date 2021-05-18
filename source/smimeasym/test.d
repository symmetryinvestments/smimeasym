module smimeasym.test;

import std.algorithm.comparison : equal;
import std.conv : to;
import std.exception : assertThrown;
import std.file : read, readText, deleteme, write;
import std.format : format;
import std.process : executeShell;
import std.stdio;

import smimeasym;

private void deleteThat(string fn) {
	import std.file : exists, remove;
	if(exists(fn)) {
		remove(fn);
	}
}

unittest {
	string[3] pubKeys =
		[ "./alice.pub"
		, "./bob.pub"
		, "./frank.pub"
		];

	string[3] privKeys =
		[ "./alice.key"
		, "./bob.key"
		, "./frank.key"
		];

	// the unencrypted data written to a file
	string data = "Hello openssl world";
	string dataFilename = deleteme ~ ".orig";
	write(dataFilename, data);
	scope(success) {
		deleteThat(dataFilename);
	}

	string encFilenameFromShell = deleteme ~ ".sh.src";

	// encrypt the data with the openssl cli
	string encFromShell = format(
			"openssl smime -encrypt -aes256 -in %s -out %s -outform PEM %--(%s %)"
			, dataFilename, encFilenameFromShell, pubKeys);
	auto encSh = executeShell(encFromShell);
	assert(encSh.status == 0, format("%s\n%s\n%s", encSh.status, encSh.output
			, encSh));
	scope(success) {
		deleteThat(encFilenameFromShell);
	}

	// decrypt data encrypt by the openssl cli
	ubyte[] encFileFromCli = cast(ubyte[])read(encFilenameFromShell);
	foreach(privKey; privKeys) {
		ubyte[] decrp = smimeDecryption(encFileFromCli, privKey);
		string decrpStr = cast(string)decrp;
		assert(data == decrpStr, format("\norig: %s\ndecr: %s", data, decrpStr));
	}

	X509*[] keys;
	X509*[] keys2;
	assertThrown(smimeEncryptionWithCerts(cast(ubyte[])data, keys));
	keys ~= null;
	assertThrown(smimeEncryptionWithCerts(cast(ubyte[])data, keys));
	keys = [];

	foreach(pubKey; pubKeys) {
		auto t = loadCert(pubKey);
		assert(t != null, pubKey);
		keys ~= t;
	}
	foreach(pubKey; pubKeys) {
		string c = readText(pubKey);
		keys2 ~= loadCertFromString(c);
	}
	ubyte[] encArray = smimeEncryptionWithCerts(cast(ubyte[])data, keys);
	ubyte[] encArray2 = smimeEncryptionWithCerts(cast(ubyte[])data, keys2);

	// encrypt with this library and write to disk
	string encFilename = deleteme ~ ".src";
	ubyte[] enc = smimeEncryption(cast(ubyte[])data, pubKeys);

	// as the aes key should be random these shouldn't match
	assert(!equal(enc, encArray));

	write(encFilename, enc);
	scope(success) {
		deleteThat(encFilename);
	}

	// decrypt with private keys
	foreach(privKey; privKeys) {
		ubyte[] decrp = smimeDecryption(enc, privKey);
		string decrpStr = cast(string)decrp;
		assert(data == decrpStr, format("\norig: %s\ndecr: %s", data, decrpStr));
	}
	foreach(privKey; privKeys) {
		ubyte[] decrp = smimeDecryption(encArray2, privKey);
		string decrpStr = cast(string)decrp;
		assert(data == decrpStr, format("\norig: %s\ndecr: %s", data, decrpStr));
	}

	// decrypt with private keys on cli
	foreach(idx, privKey; privKeys) {
		string decLibFilename = format("%s.%d.enc.lib", deleteme, idx);
		string decFromShell = format(
				"openssl smime -decrypt -in %s -out %s -inform PEM -inkey %s"
				, encFilename, decLibFilename, privKey);
		auto decSH = executeShell(decFromShell);
		assert(decSH.status == 0, format("%s\n%s\n%s", decSH.status, decSH.output
				, decFromShell));
		ubyte[] decFileFromCli = cast(ubyte[])read(decLibFilename);
		string decrpStr = cast(string)decFileFromCli;
		assert(data == decrpStr, format("\norig: %s\ndecr: %s", data, decrpStr));
		scope(success) {
			deleteThat(decLibFilename);
		}
	}
	foreach(cert; keys) {
		freeCert(cert);
	}
	foreach(cert; keys2) {
		freeCert(cert);
	}
}

unittest {
	string data = "Hello openssl world";
	string[] pubKeys = [ "dub.json"];
	assertThrown(smimeEncryption(cast(ubyte[])data, pubKeys));
}

unittest {
	string data = "Hello openssl world";
	string privKeys = "dub.json";
	assertThrown(smimeDecryption(cast(ubyte[])data, privKeys));
}

unittest {
	string data = "Hello openssl world";
	string privKeys = "alice.key";
	assertThrown(smimeDecryption(cast(ubyte[])data, privKeys));
}

unittest {
	string data = "Hello openssl world";
	string privKeys = "source";
	assertThrown(smimeDecryption(cast(ubyte[])data, privKeys));
}

unittest {
	string data = "Hello openssl world";
	string privKeys = "doesnotexist";
	assertThrown(smimeDecryption(cast(ubyte[])data, privKeys));
}

unittest {
	string notAKey = "Not a key";
	auto k = loadCertFromString(notAKey);
	assert(k is null);
}

unittest {
	auto r = cast(ubyte[])read("README.md");
	auto p = loadCert("./alice.pub");
	auto e = smimeEncryptionWithCerts(r, [p]);
	auto d = smimeDecryption(e, "./alice.key");
	write("textOrBinary.enc", e);
	assert(r == d, format("%.3s %.3s\n%s\n\n%s\n%s", r.length, d.length, r, d,
				cast(string)d));
}
