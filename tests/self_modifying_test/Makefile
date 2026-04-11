CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -fno-pie
LDFLAGS = -no-pie

TARGET = scallop_demo
SRC = main.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) 10

clean:
	rm -f $(OBJ) $(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)
	gdb ./$(TARGET)
