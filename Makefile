CFLAGS= -o0 \
	-std=gnu99 \
	-Wall \
	-Wextra \
	-Werror \
	-g -ggdb \
	-DDEBUG

CC= gcc

all: service

%.o: %.c
	$(CC) -c $(CFLAGS) $(<) -o $(@)

service: service.o
	$(CC) $(<) -o $(@)

clean:
	-rm -f *.o
	-rm -f service
	-rm -f core

.PHONY: clean all
