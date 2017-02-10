// Copyright (c) 2017 Rebecca Skinner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <stddef.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <stdarg.h>
#include <time.h>

const int EPOLL_EVENT_CNT = 10;
const char PID_PATH[] = "/var/run/example-service.pid";
const char SRV_SOCK_PATH[] = "/tmp/example-service.socket";

struct service_opts;
typedef struct service_opts service_opts_t;

int parse_int(char* input, time_t* output);
int handle_args(int argc, char** argv, service_opts_t* opts);
FILE* open_logfile(char* path);
int check_pidfile();
int handle_reload(service_opts_t*);
int open_uds_socket_srv(const char* path, FILE*);
int get_signal_fd(FILE*);
int add_fd_to_epoll(int epollfd, int fd);
int handle_socket_fd(int socketfd, FILE* logfile);
int handle_signal_fd(int signalfd, FILE* logfile);
void printlog(FILE* logfile, const char* fmt, ...);
void write_pidfile();
void showHelp();

struct service_opts {
    time_t* timeout_after;
    int* exit_with;
    char* log_to;
    FILE* log_fd;
    int nofork;
    int reload_config;
};

int main(int argc, char **argv) {
    service_opts_t opts = {};
    int listen_fd;
    int signal_fd;
    int epollfd;
    int num_fds;
    pid_t child_pid;

    struct epoll_event events[EPOLL_EVENT_CNT];
    if (-1 == handle_args(argc, argv, &opts)) {
        showHelp();
        return EXIT_FAILURE;
    }

    if (NULL == opts.log_fd) {
        opts.log_fd = stderr;
    }

    if (opts.reload_config) {
        return handle_reload(&opts);
    }

    listen_fd = open_uds_socket_srv(SRV_SOCK_PATH, opts.log_fd);

    if (-1 == listen_fd) {
        printlog(opts.log_fd, "cannot open unix socket at '%s'\n", SRV_SOCK_PATH);
        return -1;
    }

    if (-1 == (signal_fd = get_signal_fd(opts.log_fd))) {
        return -1;
    }

    if(-1 == (epollfd = epoll_create1(0))) {
        printlog(opts.log_fd, "unable to epoll: %s\n", strerror(errno));
        return -1;
    }

    if(-1 == add_fd_to_epoll(epollfd, listen_fd)) {
        printlog(opts.log_fd, "unable to add fd to epoll: %s\n", strerror(errno));
        return -1;
    }

    if(-1 == add_fd_to_epoll(epollfd, signal_fd)) {
        printlog(opts.log_fd, "unable to add fd to epoll: %s\n", strerror(errno));
        return -1;
    }

    switch (child_pid = fork()) {
    case -1:
        printlog(opts.log_fd, "error forking child: %s\n", strerror(errno));
        break;
    case 0:
        printlog(opts.log_fd, "child process starting with pid: %d\n", getpid());
        break;
    default:
        exit(0);
        break;
    }

    write_pidfile();

    for(;;) {
        if(-1 == (num_fds = epoll_wait(epollfd, events, EPOLL_EVENT_CNT, -1))) {
            printlog(opts.log_fd, "epoll_wait error: %s\n", strerror(errno));
        }
        for(int i = 0; i < num_fds; i++) {
            if (events[i].data.fd == listen_fd) {
                if(handle_socket_fd(listen_fd, opts.log_fd)) { goto finish; }
            }

            if (events[i].data.fd == signal_fd) {
                if(handle_signal_fd(signal_fd, opts.log_fd)) { goto finish; }
            }

        }
    }
finish:
    if(opts.log_fd) {
        fflush(opts.log_fd);
        fclose(opts.log_fd);
    }
    if(0 < epollfd) { close(epollfd); }
    if(0 < signal_fd) { close(signal_fd); }
    if(0 < listen_fd) { close(listen_fd); }
    return 0;
}

void printlog(FILE* logfile, const char* fmt, ...) {
    if (NULL == logfile) {
        logfile = stderr;
    }
    va_list ap;
    va_start (ap, fmt);
    fprintf(logfile, "[%lu] ", time(NULL));
    vfprintf(logfile, fmt, ap);
    va_end (ap);
}

int handle_socket_fd(int socketfd, FILE* logfile) {
    ssize_t recv_bytes = 0;
    char msg_buffer[128] = {'a'};
    msg_buffer[3] = '\0';
    if(-1 == (recv_bytes = recvfrom(socketfd, msg_buffer, 128, 0, NULL, NULL))) {
        printlog(logfile, "error reading from socket: %s\n", strerror(errno));
        return -1;
    }
    printlog(logfile, "received a %d-byte socket message: %s\n", recv_bytes, msg_buffer);
    if (!strcmp("EXIT", msg_buffer)) {
        return -1;
    }
    return 0;
}

int handle_signal_fd(int signalfd, FILE* logfile) {
    ssize_t s;
    struct signalfd_siginfo fdsi;
    if(-1 == (s = read(signalfd, &fdsi, sizeof(struct signalfd_siginfo)))) {
        printlog(logfile, "error reading from signal fd: %s\n", strerror(errno));
        return -1;
    }
    switch(fdsi.ssi_signo) {
    case SIGHUP:
        printlog(logfile, "received SIGHUP\n");
        break;
    case SIGINT:
        printlog(logfile, "received SIGINT\n");
        return -1;
        break;
    case SIGQUIT:
        printlog(logfile, "received SIGQUIT\n");
        break;
    case SIGILL:
        printlog(logfile, "received SIGILL\n");
        break;
    case SIGABRT:
        printlog(logfile, "received SIGABRT\n");
        break;
    case SIGFPE:
        printlog(logfile, "received SIGFPE\n");
        break;
    case SIGSEGV:
        printlog(logfile, "received SIGSEGV\n");
        break;
    case SIGPIPE:
        printlog(logfile, "received SIGPIPE\n");
        break;
    case SIGALRM:
        printlog(logfile, "received SIGHALRM\n");
        break;
    case SIGTERM:
        printlog(logfile, "received SIGTERM\n");
        break;
    case SIGUSR1:
        printlog(logfile, "received SIGUSR1\n");
        break;
    case SIGUSR2:
        printlog(logfile, "received SIGUSR2\n");
        break;
    case SIGCHLD:
        printlog(logfile, "received SIGCHLD\n");
    default:
        printlog(logfile, "received unknown signal: %d\n", fdsi.ssi_signo);
        break;
    }
    return 0;
}

int add_fd_to_epoll(int epollfd, int fd) {
    struct epoll_event ev;
    if (epollfd < 0 || fd < 0) { return -1; }
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

int get_signal_fd(FILE* logfd) {
    sigset_t sigmask;
    int signal_fd;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGQUIT);
    sigaddset(&sigmask, SIGILL);
    sigaddset(&sigmask, SIGABRT);
    sigaddset(&sigmask, SIGFPE);
    sigaddset(&sigmask, SIGSEGV);
    sigaddset(&sigmask, SIGPIPE);
    sigaddset(&sigmask, SIGALRM);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGUSR2);
    sigaddset(&sigmask, SIGCHLD);

    if(sigprocmask(SIG_BLOCK, &sigmask, NULL)) {
        printlog(logfd, "error masking signals: %s\n", strerror(errno));
        return -1;
    }

    if (-1 == (signal_fd = signalfd(-1, &sigmask, SFD_NONBLOCK))) {
        printlog(logfd, "error creating signal fd: %s\n", strerror(errno));
        return -1;
    }

    return signal_fd;
}

int handle_reload(__attribute__((unused)) __attribute__((unused))service_opts_t* opts) {
    return 0;
}

// Creates and binds to a unix domain socket
int open_uds_socket_srv(const char* path, FILE* logfd) {
    int fd;
    socklen_t size;
    struct sockaddr_un sa;

    if (unlink(path)) {
        if (ENOENT != errno) {
            printlog(logfd, "unable to remove socket at '%s': %s\n", SRV_SOCK_PATH, strerror(errno));
            return -1;
        }
    }


    if (-1 == (fd = socket(PF_LOCAL, SOCK_DGRAM, 0))) {
        printlog(logfd, "error getting socket: %s\n", strerror(errno));
        return -1;
    }

    printlog(logfd, "socket(PF_LOCAL, SOCK_DGRAM) returned %d\n", fd);

    memset(&sa, 0, sizeof(struct sockaddr_un));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, path, sizeof(sa.sun_path));
    sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

    size = (offsetof (struct sockaddr_un, sun_path) + strlen(sa.sun_path));
    if (bind(fd, (struct sockaddr*)&sa, size)) {
        printlog(logfd, "unable to bind to socket: %s\n", strerror(errno));
        goto error;
    }

    printlog(logfd, "open_uds_socket_srv: returning %d\n", fd);
    return fd;
error:
    if(fd > 0) {
        close(fd);
    }
    return -1;
}

// Connects to a unix domain socket
// int open_uds_socket_cli(char* path) {
//    return -1;
// }

// check_pidfile attempts to determine if an instance of the process
// is already running.  It returns -1 if it believes a process is
// already running, and 0 otherwise. We guess that the process isn't
// running if any of the following are true:
//
//     - If the pidfile is missing or empty, return 0
//
//     - If the pidfile contains a pid that does not have an existing
//       entry in /proc
//
//     - if the pidfile contains a pid that exists in /proc, but
//       /proc/<pidfile>/exe is not the same binary as /proc/self/exe
int check_pidfile() {
    struct stat st;
    FILE* f;
    char* pidfile_contents = 0;
    int rv = -1;

    if (-1 == stat(PID_PATH, &st)) {
        rv = 0;
        goto cleanup;
    }

    pidfile_contents = malloc(st.st_size);
    if (NULL == (f = fopen(PID_PATH, "r"))) {
        printlog(stderr, "Error opening pidfile: %s\n", strerror(errno));
        goto cleanup;
    }

cleanup:
    if (NULL != f) {
        fclose(f);
    }

    if (NULL != pidfile_contents) {
    }
    return rv;
}

void write_pidfile() {
    FILE* f;
    if(-1 == unlink(PID_PATH)) {
        if (ENOENT != errno) {
            exit(-1);
        }
    }
    if(NULL == (f = fopen(PID_PATH, "w"))) {
        fprintf(stderr, "unable to create PIDfile\n");
        exit(-1);
    }
    fprintf(f, "%d", getpid());
    fflush(f);
    fclose(f);
}

void showHelp() {
    fprintf(stderr, "example-service: a basic systemd-aware service that acts as an example and testbed.\n");
    fprintf(stderr, "Usage: service [options]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr,"\n");
    fprintf(stderr, "\t --fail-after <time> \t The service will fail after TIME seconds.  \n");
    fprintf(stderr, "\t                     \t if an exit code was specified with --exit-with, then\n");
    fprintf(stderr, "\t                     \t that code will be used, otherwise exit with EXIT_SUCCESS\n");
    fprintf(stderr,"\n");
    fprintf(stderr, "\t --exit-with <int>   \t The service will exit with this error code, if specified.  If\n");
    fprintf(stderr, "\t                     \t --exit-with is not specified, exit with EXIT_SUCCESS\n");
    fprintf(stderr,"\n");
    fprintf(stderr, "\t --log-to <file>     \t Specifies the path to the file that log data will be written to.\n");
    fprintf(stderr, "\t                     \t if this is not specified, logs will be written to \n");
    fprintf(stderr, "\t                     \t /var/log/example-service/service.log\n");
    fprintf(stderr,"\n");
    fprintf(stderr, "\t --foreground        \t If --foreground is set the do not daemonize\n");
    fprintf(stderr,"\n");
    fprintf(stderr, "\t --reload            \t Tell running instance of the service to reload it's config\n");
    fprintf(stderr,"\n");
    fprintf(stderr, "\t --help              \t show this help message and exit\n");
}

int handle_args(int argc, char** argv, service_opts_t *opts) {
    int c = -1;
    int opt_idx = 0;
    long parsed_time = 0;
    long parsed_exit_time = 0;
    static int foreground_flag = 0;

    if (NULL == opts) {
        return -1;
    }

    static struct option allowed_opts[] = {
        {"fail-after", required_argument, 0, 'a'},
        {"exit-with", required_argument, 0, 'b'},
        {"log-to", required_argument, 0, 'c'},
        {"foreground", no_argument, &foreground_flag, 1},
        {"help", no_argument, 0, 'h'},
        {"reload",no_argument,0,'r'},
        {},
    };

    while (-1 != (c = getopt_long(argc, argv, "a:b:c:hr", allowed_opts, &opt_idx))) {
        switch (c) {
        case 'a':
            if (NULL == optarg) {
                fprintf(stderr, "no time specified for --fail-after\n");
                goto error;
            }
            if (-1 == parse_int(optarg, &parsed_time)) {
                fprintf(stderr, "unable to parse '%s' into a time value\n", optarg);
                goto error;
            }
            opts->timeout_after = malloc(sizeof(time_t));
            *(opts->timeout_after) = (time_t)parsed_time;
            break;
        case 'b':
            if (NULL == optarg) {
                fprintf(stderr, "no exit code specified for --exit-with\n");
                goto error;
            }
            if (-1 == parse_int(optarg, &parsed_exit_time)) {
                fprintf(stderr, "unable to parse '%s' into an exit code\n", optarg);
                goto error;
            }
            opts->exit_with = malloc(sizeof(int));
            *(opts->exit_with) = (int)(parsed_exit_time);
            break;
        case 'c':
            if (NULL == optarg) {
                fprintf(stderr, "no path specified for --log-to\n");
                goto error;
            }
            opts->log_to = strdup(optarg);
            if (NULL == (opts->log_fd = open_logfile(optarg))) {
                goto error;
            }
            break;
        case 'r':
            opts->reload_config = 1;
            return 0;
        case 'h':
        default:
            goto error;
        }
    }
    return 0;

error:
    return -1;
}

int parse_int(char* input, long* output) {
    long l;
    if (NULL == input || NULL == output) {
        return -1;
    }
    errno = 0;
    l = strtol(input, NULL, 10);
    if (errno != 0) {
        fprintf(stderr, "error parsing time: %s\n", strerror(errno));
        return -1;
    }
    *output = l;
    return 0;
}

FILE* open_logfile(char* path) {
    if (NULL == path) {
        return NULL;
    }

    if (0 == strcmp(path, "-") ||
        0 == strcmp(path, "stdout")) {
        return stdout;
    }

    if (0 == strcmp(path, "stderr")) {
        return stderr;
    }

    return fopen(path, "a+");
}
