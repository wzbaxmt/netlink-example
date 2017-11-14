CC = gcc
CFLAGS = -Wextra -Wall -g -O0 -DDEBUG -lpthread

SOURCES = main.c
BIN_NAME = mynetlink

all: $(BIN_NAME)

$(BIN_NAME): $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $@
	cp $(BIN_NAME) ../$(BIN_NAME)
clean:
	rm -rf $(BIN_NAME) ../$(BIN_NAME)
