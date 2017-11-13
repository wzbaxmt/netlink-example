CC = gcc
CFLAGS = -Wextra -Wall -g -O0 -DDEBUG

SOURCES = main.c
BIN_NAME = mynetlink
TARGET = ../$(BIN_NAME)

all: $(TARGET)

$(TARGET): $(BIN_NAME)
	cp $< $@

$(BIN_NAME): $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(BIN_NAME) $(TARGET)
