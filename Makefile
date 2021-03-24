chelper.o: source/smimeasym/smime.c
	gcc -Wall -O0 -c $? -o $@ `pkg-config --cflags --libs openssl` -lcrypto
	dub clean
