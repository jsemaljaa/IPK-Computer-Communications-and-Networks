CC = gcc
CFLAGS = -lpcap -std=gnu99 -Wall -Werror -pedantic
TARGET = ipk-sniffer

all: $(TARGET)

ipk-sniffer: $(TARGET).c
		$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)