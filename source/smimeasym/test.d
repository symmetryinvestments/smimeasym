module smimeasym.test;

import std.stdio;
import std.file : read, readText, deleteme, write;
import std.format : format;
import std.process : executeShell;
import std.conv : to;

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

	// encrypt with this library and write to disk
	string encFilename = deleteme ~ ".src";
	ubyte[] enc = smimeEncryption(cast(ubyte[])data, pubKeys);
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
}
