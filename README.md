## Sample Daemon

A well-behaved daemon that does nothing (except log).

This program aims to act as an extremely basic daemon that can be run on Linux
systems for testing purposes.  It requires systemd, and provides systemd unit
files, along with a [converge](https://github.com/asteris-llc/converge) module
for installation.

It opens a unix doman socket and masks all unix signals.  It will idle until a
message is written to it's socket, or it receives a signal.  Messages and
signals are loggged with the current time in the log file.  Nothing else is
done.

## Building from Source

### Debian & Ubuntu

```
$ apt-get install git build-essential libsystemd-dev
$ git clone https://github.com/rebeccaskinner/example-service.git
$ cd example-service
$ make
$ converge apply --local install-service.hcl # or 'make install'
```
