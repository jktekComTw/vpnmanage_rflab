CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lncurses -lssl -lcrypto
TARGET = manage
SRC = managevpnusers.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET) vpnusers.db

.PHONY: all clean
