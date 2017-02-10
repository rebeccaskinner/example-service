// Copyright (c) 2017 Asteris, LLC
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

#define _GNU_SOURCE
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
#include <linux/limits.h>
#include <systemd/sd-daemon.h>

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
    time_t started_at = time(NULL);

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

    if(!check_pidfile()) {
        printlog(stderr, "process already running\n");
        return -1;
    }

    if (!opts.nofork) {
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
    }

    write_pidfile();

    printlog(opts.log_fd, "Process started at %lu\n", started_at);

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

    if (NULL != opts.timeout_after) {
        printlog(opts.log_fd, "timing out run after %lu seconds\n", *opts.timeout_after);
        alarm(*opts.timeout_after);
    }

    sd_notify(0, "READY=1");

    for(;;) {
        if(-1 == (num_fds = epoll_wait(epollfd, events, EPOLL_EVENT_CNT, -1))) {
            printlog(opts.log_fd, "epoll_wait error: %s\n", strerror(errno));
        }
        for(int i = 0; i < num_fds; i++) {
            if (events[i].data.fd == listen_fd) {
                if(handle_socket_fd(listen_fd, opts.log_fd)) { goto finish; }
            }

            if (events[i].data.fd == signal_fd) {
                int this_signal = handle_signal_fd(signal_fd, opts.log_fd);
                if (-1 == this_signal) {
                    goto finish;
                }
                if (SIGALRM == this_signal && NULL != opts.timeout_after) {
                    if (*opts.timeout_after <= (time(NULL) - started_at)) {
                        printlog(opts.log_fd, "timeout alarm signaled, exiting\n");
                        goto finish;
                    } else {
                        alarm(1);
                    }
                }
            }

        }
    }

finish:
    sd_notify(0, "STOPPING=1");
    if(opts.log_fd) {
        fflush(opts.log_fd);
        fclose(opts.log_fd);
    }
    if(0 < epollfd) { close(epollfd); }
    if(0 < signal_fd) { close(signal_fd); }
    if(0 < listen_fd) { close(listen_fd); }
    if (NULL != opts.exit_with) {
        exit(*opts.exit_with);
    }
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

    if (!strcmp("EXIT", msg_buffer)) {
        return -1;
    }

    if (!strcmp("RELOAD", msg_buffer)) {
        sd_notify(0, "RELOADING=1\n");
    }

    printlog(logfile, "received a %d-byte socket message: %s\n", recv_bytes, msg_buffer);

    if(!strcmp("RELOAD", msg_buffer)) {
        sd_notify(0, "READY=1");
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
        printlog(logfile, "received SIGALRM\n");
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
    return fdsi.ssi_signo;
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

int handle_reload(__attribute__((unused)) service_opts_t* opts) {
    int fd;
    socklen_t size;
    struct sockaddr_un sa;

    static const char msg[] = "RELOAD";

    if(check_pidfile()) {
        printlog(stderr, "cannot reload process, not running\n");
        return -1;
    }

    if(-1 == (fd = socket(PF_LOCAL, SOCK_DGRAM, 0))) {
        printlog(stderr, "failed to open socket: %s\n", strerror(errno));
    }


    memset(&sa, 0, sizeof(struct sockaddr_un));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path, SRV_SOCK_PATH, sizeof(sa.sun_path));
    sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

    size = (offsetof (struct sockaddr_un, sun_path)) + strlen(sa.sun_path);

    if(-1 == sendto(fd, msg,  sizeof(msg), 0, (struct sockaddr*)&sa, size)) {
        printlog(stderr, "failed to send message to socket: %s\n", strerror(errno));
    }

    close(fd);
    return 0;
}

// Creates and binds to a unix domain socket
int open_uds_socket_srv(const char* path, FILE* logfd) {
    int fd;
    socklen_t size;
    struct sockaddr_un sa;

    printlog(logfd, "%d sockets inherited from systemd\n", sd_listen_fds(0));
    if (1 == sd_listen_fds(0)) {
        if(sd_is_socket(SD_LISTEN_FDS_START,
                        PF_LOCAL,
                        SOCK_DGRAM,
                        -1)) {
            return SD_LISTEN_FDS_START;
        }
        printlog(logfd, "received an invalid local socket from systemd");
    }

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

    if(-1 == chmod(SRV_SOCK_PATH, S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH)) {
        printlog(stderr, "failed to set ownership on socket: %s\n", strerror(errno));
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
    int fd = -1;
    char* pidfile_contents = 0;
    char exe_path [PATH_MAX] = {0};
    char my_path [PATH_MAX] = {0};
    char real_exe_path [PATH_MAX] = {0};
    int rv = -1;

    if (-1 == stat(PID_PATH, &st)) {
        rv = 0;
        printlog(stderr, "no pidfile at %s\n", PID_PATH);
        goto cleanup;
    }

    pidfile_contents = malloc(st.st_size);
    if (-1 == (fd = open(PID_PATH, O_RDONLY))) {
        printlog(stderr, "Error opening pidfile: %s\n", strerror(errno));
        goto cleanup;
    }

    if(!read(fd, pidfile_contents, st.st_size)) {
        printlog(stderr, "Error reading pidfile: %s\n", strerror(errno));
        goto cleanup;
    }


    if(-1 == readlink("/proc/self/exe", my_path, sizeof(my_path) - 1)) {
        printlog(stderr, "unable to read link for /proc/self/exe: %s\n", strerror(errno));
        goto cleanup;
    }

    snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", pidfile_contents);
    if(-1 == readlink(exe_path, real_exe_path, sizeof(real_exe_path) - 1)) {
        if (errno != ENOENT) {
            printlog(stderr, "unable to get full path of %s: %s\n", exe_path, strerror(errno));
            goto cleanup;
        }
    }

    rv = strcmp(my_path, real_exe_path);

cleanup:
    if (0 < fd) {close(fd);}
    if (NULL != pidfile_contents) {free(pidfile_contents);}
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
    static const char* helpstr =
    "example-service: a basic systemd-aware service that acts as an example and testbed.\n"
    "Usage: service [options]\n"
    "Options:\n"
    "\n"
    "\t --fail-after <time> \t The service will fail after TIME seconds.  \n"
    "\t                     \t if an exit code was specified with --exit-with, then\n"
    "\t                     \t that code will be used, otherwise exit with EXIT_SUCCESS\n"
    "\n"
    "\t --exit-with <int>   \t The service will exit with this error code, if specified.  If\n"
    "\t                     \t --exit-with is not specified, exit with EXIT_SUCCESS\n"
    "\n"
    "\t --log-to <file>     \t Specifies the path to the file that log data will be written to.\n"
    "\t                     \t if this is not specified, logs will be written to \n"
    "\t                     \t /var/log/example-service/service.log\n"
    "\n"
    "\t --foreground        \t If --foreground is set the do not daemonize\n"
    "\n"
    "\t --reload            \t Tell running instance of the service to reload it's config\n"
    "\n"
    "\t --help              \t show this help message and exit\n";

    fprintf(stderr, "%s", helpstr);
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
        {"foreground", no_argument, &foreground_flag, 1},
        {"fail-after", required_argument, 0, 'a'},
        {"exit-with", required_argument, 0, 'b'},
        {"log-to", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"reload",no_argument,0,'r'},
        {},
    };

    while (-1 != (c = getopt_long(argc, argv, "a:b:c:hr", allowed_opts, &opt_idx))) {
        switch (c) {
        case 0:
            opts->nofork = foreground_flag;
            break;
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
