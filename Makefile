CFLAGS= -Os -std=c99 -Wall -Wextra -Werror
LFLAGS= -lsystemd
CC= gcc

all: service

%.o: %.c
	$(CC) -c $(CFLAGS) $(<) -o $(@)

service: service.o
	$(CC) $(<) $(LFLAGS) -o $(@)
	strip $(@)

clean:
	-rm -f *.o
	-rm -f service
	-rm -f core

.PHONY: clean all
