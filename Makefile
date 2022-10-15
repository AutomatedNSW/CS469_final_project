CC := gcc
LDFLAGS := -lssl -lcrypto
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: ssl-client ssl-server server-backup

ssl-client: ssl-client.o
	$(CC) $(CFLAGS) -o ssl-client ssl-client.o $(LDFLAGS)

ssl-client.o: ssl-client.c
	$(CC) $(CFLAGS) -c ssl-client.c

ssl-server: ssl-server.o
	$(CC) $(CFLAGS) -o ssl-server ssl-server.o $(LDFLAGS)

ssl-server.o: ssl-server.c
	$(CC) $(CFLAGS) -c ssl-server.c

server-backup: server-backup.o
	$(CC) $(CFLAGS) -o server-backup server-backup.o $(LDFLAGS)

server-backup.o: server-backup.c
	$(CC) $(CFLAGS) -c server-backup.c

clean:
	rm -f ssl-server ssl-server.o ssl-client ssl-client.o server-backup server-backup.o
