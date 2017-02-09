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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

const char PID_PATH[] = "/var/run/example-service.pid";

struct service_opts;
typedef struct service_opts service_opts_t;

int parse_int(char* input, time_t* output);
int handle_args(int argc, char** argv, service_opts_t* opts);
FILE* open_logfile(char* path);
int check_pidfile();

#ifdef DEBUG
void show_service_opts(service_opts_t* s);
#endif

void showHelp();

struct service_opts {
    time_t* timeout_after;
    int* exit_with;
    char* log_to;
    FILE* log_fd;
    int nofork;
};

int main(int argc, char **argv) {
    service_opts_t opts = {};
    if (-1 == handle_args(argc, argv, &opts)) {
        showHelp();
        return EXIT_FAILURE;
    }

    #ifdef DEBUG
    show_service_opts(&opts);
    #endif

}

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
        fprintf(stderr, "Error opening pidfile: %s\n", strerror(errno));
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
        {},
    };

    while (-1 != (c = getopt_long(argc, argv, "a:b:c:", allowed_opts, &opt_idx))) {
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

#ifdef DEBUG
void show_service_opts(service_opts_t* opts) {
    if (!opts) {
        printf("configured options: NULL\n");
        return;
    }
    printf("configured options:\n");
    printf("\t Timeout after: ");
    if (opts->timeout_after) {
        printf("%ld\n", *(opts->timeout_after));
    } else {printf("NULL\n");}
    printf("\t Exit With: ");
    if (opts->exit_with) {
        printf("%d\n", *(opts->exit_with));
    } else { printf("NULL\n"); }
    printf("\t Logging to: ");
    if (opts->log_to && opts->log_fd) {
        printf("%s (%d)\n", opts->log_to, fileno(opts->log_fd));
    } else { printf("unknown\n"); }
}
#endif
