CC = gcc
CFLAGS = -lpcap -Wall -Werror
TARGET = ipk-sniffer

all: $(TARGET)

ipk-sniffer: $(TARGET).c
		$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)