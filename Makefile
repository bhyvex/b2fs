CC				= gcc
CFLAGS		= -g -Wall -Wextra -std=gnu99 -D_FILE_OFFSET_BITS=64 -DJSMN_PARENT_LINKS
LDFLAGS		= -lpthread -lfuse -lcurl
LIBB64		= $(wildcard src/b64/*.c)
JSMN			= $(wildcard src/jsmn/*.c)
XXHASH		= $(wildcard src/xxhash/*.c)
STRUCTS		= $(wildcard src/structures/*.c)
B64OBJ		= $(addprefix obj/b64/, $(notdir $(LIBB64:.c=.o)))
JSMNOBJ		= $(addprefix obj/jsmn/, $(notdir $(JSMN:.c=.o)))
XXOBJ			= $(addprefix obj/xxhash/, $(notdir $(XXHASH:.c=.o)))
STRUCTOBJ	= $(addprefix obj/structs/, $(notdir $(STRUCTS:.c=.o)))
B2FS			= bin/b2fs
DIRS			= bin obj/b64 obj/jsmn obj/xxhash obj/structs

$(B2FS): src/b2fs.c $(B64OBJ) $(JSMNOBJ) $(XXOBJ) $(STRUCTOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

obj/b64/%.o: src/b64/%.c $(DIRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

obj/jsmn/%.o: src/jsmn/%.c $(DIRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

obj/xxhash/%.o: src/xxhash/%.c $(DIRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

obj/structs/%.o: src/structures/%.c $(DIRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

$(DIRS):
	mkdir bin
	mkdir -p obj/b64
	mkdir -p obj/jsmn
	mkdir -p obj/xxhash
	mkdir -p obj/structs

clean:
	rm -rf bin
	rm -rf obj
