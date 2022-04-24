CC = gcc
CFLAGS = -lpcap
TARGET = ipk-sniffer

all: $(TARGET)

ipk-sniffer: $(TARGET).c
		$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)