libsmimeasymc.a: chelper.o
	$(AR) rcs $@ $?

chelper.o: source/smimeasym/smime.c
	$(CC) -Wall -O0 -c $? -o $@ `pkg-config --cflags --libs openssl` -lcrypto
