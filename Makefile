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

install: service
	cp example.service /lib/systemd/system/
	cp example.socket /lib/systemd/system
	cp service /usr/sbin/example-service

uninstall:
	-rm -f /lib/systemd/system/example.service
	-rm -f /lib/systemd/system/example.socket
	-rm -f /usr/sbin/example-service

.PHONY: clean all
