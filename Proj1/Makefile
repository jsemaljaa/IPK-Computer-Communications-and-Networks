CC = gcc
CFLAGS = -Wall -Werror
TARGET = hinfosvc

all: $(TARGET)

hinfosvc: $(TARGET).c
	$(CC) $(CFLAGS) $(TARGET).c -o $(TARGET)

clean:
	$(RM) $(TARGET)