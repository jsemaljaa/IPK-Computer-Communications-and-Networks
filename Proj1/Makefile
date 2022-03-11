CC = gcc
CFLAGS = -Wall -Werror
TARGET = hinfosvc

all: $(TARGET)

hinfosvc: $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)