CC = gcc
CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes
LIBS = -lccn -lcrypto -lrt

PROGRAM_CL = cbr-client
PROGRAM_SR = cbr-server
																				
all: $(PROGRAM_CL) $(PROGRAM_SR)

cbr-client: cbr-client.o
	$(CC) $(CFLAGS) -o cbr-client cbr-client.o $(LIBS)

cbr-client.o:
	$(CC) $(CFLAGS) -c cbr-client.c

cbr-server: cbr-server.o
	$(CC) $(CFLAGS) -o cbr-server cbr-server.o $(LIBS)

cbr-server.o:
	$(CC) $(CFLAGS) -c cbr-server.c							 

clean:
	rm -f *.o
	rm -f $(PROGRAM_CL) $(PROGRAM_SR)
