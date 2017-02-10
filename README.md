## Sample Daemon

A well-behaved daemon that does nothing (except log).

This program aims to act as an extremely basic daemon that can be run on Linux
systems for testing purposes.  It provides init scripts for SysV init and
systemd.  It opens a unix doman socket and masks all unix signals.  It will idle
until a message is written to it's socket, or it receives a signal.  Messages
and signals are loggged with the current time in the log file.  Nothing else is
done.
