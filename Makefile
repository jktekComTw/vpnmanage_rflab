CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lncurses -lssl -lcrypto
TARGET = manage
SRC = managevpnusers.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET) vpnusers.db

.PHONY: all clean
