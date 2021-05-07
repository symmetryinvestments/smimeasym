libsmimeasymc.a: chelper.o
	ar rcs $@ $?

chelper.o: source/smimeasym/smime.c
	$(CC) -Wall -O0 -c $? -o $@ `pkg-config --cflags --libs openssl` -lcrypto
	ar rcs libout.a out.o
