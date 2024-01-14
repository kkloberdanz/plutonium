#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * TODO:
 * - User definder handler function pointers
 * - Fix up request reading
 * - Don't read content until a read_content() function is called
 * - Add sqlite DB
 * - Add S7 scheme interpreter
 * - Replace fork model with thread pool (wrkq.c)
 *   + Each thread will get its own sqlite conn in thread local storage.
 * - Move main to an option file so that the rest of this project can be
 *   re-used as a library.
 */

static const char *get_routes[] = {"/api"};
static const size_t num_get_routes = sizeof(get_routes) / sizeof(*get_routes);

typedef const char *const str;

static str reply_200 =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Content-Length: 149\r\n"
    "Server: Plutonium\r\n"
    "Accept-Ranges: bytes\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<html>\n"
    "  <head>\n"
    "    <title>An Example Page</title>\n"
    "  </head>\n"
    "  <body>\n"
    "    <p>Hello World, this is a very simple HTML document.</p>\n"
    "  </body>\n"
    "</html>\n";
static ssize_t reply_200_len = 0;

static str reply_307 = "HTTP/1.1 307 Temporary Redirect\r\n"
                       "Location: https://google.com\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n";
static ssize_t reply_307_len = 0;

static str reply_400 = "HTTP/1.1 400 Bad Request\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n";
static ssize_t reply_400_len = 0;

static str reply_404 = "HTTP/1.1 404 Not Found\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n";
static ssize_t reply_404_len = 0;

static str reply_411 = "HTTP/1.1 411 Length Required\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n";
static ssize_t reply_411_len = 0;

static str reply_431 = "HTTP/1.1 431 Request Header Fields Too Large\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n";
static ssize_t reply_431_len = 0;

static str reply_500 = "HTTP/1.1 500 Internal Server Error\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n";
static ssize_t reply_500_len = 0;

enum status_code {
    HTTP_OK = 200,
    HTTP_TEMPORARY_REDIRECT = 307,
    HTTP_BAD_REQUEST = 400,
    HTTP_NOT_FOUND = 404,
    HTTP_LENGTH_REQUIRED = 411,
    HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    HTTP_INTERNAL_SERVER_ERROR = 500
};

enum {
    READ_BUF_SIZE = (1 << 12)
};

static ssize_t read_header(int new_socket, char *buf) {
    ssize_t idx = 0;

    idx = read(new_socket, buf, READ_BUF_SIZE - 1);
    if (idx < 0) {
        perror("read client socket");
        goto done;
    }

    buf[idx] = 0;

done:
    return idx;
}

static void write_header(int new_socket, enum status_code code, long sz) {
    char buf[READ_BUF_SIZE] = {0};
    (void)code;

    sprintf(
        buf,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %ld\r\n"
        "\r\n",
        sz
    );

    write(new_socket, buf, strlen(buf));
}

static void canned_reply(int new_socket, enum status_code code) {
    ssize_t nwritten = 0;
    ssize_t n = 0;
    const char *reply_msg = NULL;
    int reply_len = 0;

    switch (code) {

    case HTTP_OK:
        reply_msg = reply_200;
        reply_len = reply_200_len;
        break;

    case HTTP_TEMPORARY_REDIRECT:
        reply_msg = reply_307;
        reply_len = reply_307_len;
        break;

    case HTTP_BAD_REQUEST:
        reply_msg = reply_400;
        reply_len = reply_400_len;
        break;

    case HTTP_NOT_FOUND:
        reply_msg = reply_404;
        reply_len = reply_404_len;
        break;

    case HTTP_LENGTH_REQUIRED:
        reply_msg = reply_411;
        reply_len = reply_411_len;
        break;

    case HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE:
        reply_msg = reply_431;
        reply_len = reply_431_len;
        break;

    case HTTP_INTERNAL_SERVER_ERROR:
    default:
        reply_msg = reply_500;
        reply_len = reply_500_len;
        break;
    }

    while (nwritten < reply_len) {
        n = write(new_socket, reply_msg, reply_len - nwritten);
        if (n < 0) {
            perror("failed to write reply");
            goto done;
        }

        if (n == 0) {
            goto done;
        }

        nwritten += n;
    }

done:
    return;
}

static void send_to_socket(int new_socket, int fd, off_t nbytes) {
    off_t offset = 0;

    while (nbytes > 0) {
        ssize_t sent_bytes =
            sendfile(fd, new_socket, offset, &nbytes, NULL, 0);

        if (sent_bytes == -1) {
            return;
        }

        offset += sent_bytes;
        nbytes -= sent_bytes;

        if (sent_bytes == 0 && nbytes > 0) {
            continue;
        }
    }
}

static void handle_route(int new_socket, const char *route) {
    (void)new_socket;
    (void)route;

    /* TODO: implement custom routes */
    canned_reply(new_socket, HTTP_INTERNAL_SERVER_ERROR);
}

static void child(int new_socket) {
    char *path = NULL;
    char *length_str = NULL;
    unsigned long given_content_length = 0;
    long header_length = 0;
    char *header = NULL;
    char *header_end = NULL;
    char *content = NULL;
    char buf[READ_BUF_SIZE] = {0};
    unsigned long content_idx = 0;
    char *content_buf = NULL;
    int rc = 0;
    ssize_t idx = 0;

    idx = read_header(new_socket, buf);
    if (rc != 0) {
        goto done;
    }

    length_str = strstr(buf, "Content-Length: ");
    if (!length_str) {
        /* If no Content-Length provided, then assume there is no content */
        header = strdup(buf);
        goto handle_request;
    }

    length_str += strlen("Content-Length: ");
    given_content_length = atol(length_str);

    header_end = strstr(buf, "\r\n\r\n");
    if (!header_end) {
        fprintf(stderr, "no HTTP header end provided, i.e., \\r\\n\\r\\n\n");
        canned_reply(new_socket, HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
        goto done;
    }

    header_length = header_end - buf;

    content = calloc(given_content_length, 1);
    if (!content) {
        perror("calloc: failed to allocate memory for HTTP content");
        goto done;
    }

    content_buf = header_end + strlen("\r\n\r\n");

    memcpy(content, content_buf, idx); /* NOLINT */

    buf[header_length] = 0;
    header = strdup(buf);

    content_idx = idx - (header_length + strlen("\r\n\r\n"));

    for (;;) {
        if (content_idx == given_content_length) {
            break;
        }

        idx = read(new_socket, buf, READ_BUF_SIZE);
        if (idx < 0) {
            perror("read client socket");
            goto done;
        }

        if (idx == 0) {
            break;
        }

        if ((content_idx + idx) > given_content_length) {
            /* Incorrect length given in HTTP header.
             * Won't attempt to process request further. */
            canned_reply(new_socket, HTTP_LENGTH_REQUIRED);
            goto done;
        }

        memcpy(content + content_idx, buf, idx); /* NOLINT */

        content_idx += idx;
    }

handle_request:
    /* TODO: handle request here */

    if (strncmp(header, "GET ", strlen("GET ")) == 0) {
        /* get path to file and remove junk after the path */
        char *space = NULL;
        size_t i;
        int fd;

        path = strdup(header + strlen("GET "));
        if (!path) {
            goto fail;
        }

        space = strstr(path, " ");
        if (!space) {
            goto fail;
        }
        *space = '\0';

        fprintf(stderr, "GET - %s\n", path);
        for (i = 0; i < num_get_routes; i++) {
            if (!strcmp(path, get_routes[i])) {
                /* Found a registered route
                 * Will use a registered route handler */
                handle_route(new_socket, path);
                goto done;
            }
        }

        if (!strcmp(path, "/")) {
            strcpy(path, "/index.html");
        }

        /* check if the file exists */
        fd = open(path, O_RDONLY);
        if (fd != -1) {
            struct stat file_stat;

            if (fstat(fd, &file_stat) == -1) {
                perror("fstat");
                return;
            }

            write_header(new_socket, HTTP_OK, file_stat.st_size);
            send_to_socket(new_socket, fd, file_stat.st_size);
            close(fd);
            goto done;
        }
        perror("open");

        /* if not, then return a 404 */
        canned_reply(new_socket, HTTP_NOT_FOUND);
        goto done;
    }

fail:
    canned_reply(new_socket, HTTP_BAD_REQUEST);

done:
    free(header);
    free(content);
    free(path);
}

static int drop_privileges(uid_t uid) {
    int rc = 0;
    gid_t list[1];
    const size_t len = sizeof(list) / sizeof(*list);

    list[0] = uid;

    rc = setgroups(len, list);
    if (rc) {
        perror("setgroups");
        goto done;
    }

    rc = setgid(uid);
    if (rc) {
        perror("setgid");
        goto done;
    }

    rc = setuid(uid);
    if (rc) {
        perror("setuid");
        goto done;
    }

done:
    return rc;
}

int main(void) {
    struct timeval tv;
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    size_t addrlen = sizeof(address);
    short port = 8888;
    int rc = 0;
    char pwd[READ_BUF_SIZE] = {0};

    signal(SIGCHLD, SIG_IGN);

    getcwd(pwd, READ_BUF_SIZE - 1);

    rc = chroot(pwd);
    if (rc) {
        perror("chroot");
        exit(EXIT_FAILURE);
    }

    reply_200_len = strlen(reply_200);
    reply_307_len = strlen(reply_307);
    reply_400_len = strlen(reply_400);
    reply_404_len = strlen(reply_404);
    reply_411_len = strlen(reply_411);
    reply_431_len = strlen(reply_431);
    reply_500_len = strlen(reply_500);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    rc = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (rc != 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    rc = bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    if (rc != 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    rc = listen(server_fd, 10);
    if (rc != 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    rc = drop_privileges(501);
    if (rc) {
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "plutonium: listening on port: %d\n", port);
    for (;;) {
        pid_t pid;
        int new_socket;

        new_socket = accept(
            server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen
        );

        if (new_socket < 0) {
            perror("accept");
            continue;
        }

        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(
            new_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)
        );

        pid = fork();
        switch (pid) {
        case -1:
            /* error */
            perror("fork failed");
            close(new_socket);
            break;

        case 0:
            /* child */
            close(server_fd);
            child(new_socket);
            close(new_socket);
            return rc;

        default:
            /* parent */
            close(new_socket);
            break;
        }
    }

    return rc;
}
