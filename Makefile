chelper.o: source/smimeasym/smime.c
	$(CC) -Wall -O3 -c $? -o $@ -I /usr/local/ssl/include -L /usr/local/ssl/lib
