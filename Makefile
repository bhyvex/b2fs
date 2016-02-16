CC				= gcc
CFLAGS		= -g -std=gnu99 -D_FILE_OFFSET_BITS=64
LDFLAGS		= -lpthread -lfuse -lcurl
LIBB64		= $(wildcard src/b64/*.c)
OBJ				= $(addprefix obj/, $(notdir $(LIBB64:.c=.o)))
B2FS			= src/b2fs.c
DIRS			= bin obj

$(B2FS): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o bin/b2fs $@ $^

obj/%.o: src/b64/%.c $(DIRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

$(DIRS):
	mkdir bin
	mkdir obj

clean:
	rm -rf bin
	rm -rf obj
