CC := gcc
WFLAGS := -Wall -Werror
DEBUG := 0
BUILD := 0.0.1

.PHONY: clean

SOURCE_FILES := \
	orion.c

OBJECT_FILES := ${SOURCE_FILES:.c=.o}

DEP_FILES := \
	orion.h

orion: $(OBJECT_FILES)
	$(CC) $(WFLAGS) -o orion $(OBJECT_FILES)

$(OBJECT_FILES): $(SOURCE_FILES) $(DEP_FILES)
ifeq ($(DEBUG), 1)
	$(CC) $(WFLAGS) -g -DDEBUG -c $^
else
	$(CC) $(WFLAGS) -c $^
endif

clean:
	rm *.o
