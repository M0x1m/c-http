#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define da_append(da, x) \
    do { \
        if ((da)->count >= (da)->capacity) { \
            (da)->capacity = (da)->capacity ? (da)->capacity*2 : 1; \
            (da)->items = realloc((da)->items, sizeof(*(da)->items)*(da)->capacity); \
            assert((da)->items && "Buy more RAM"); \
        } \
        (da)->items[(da)->count++] = x; \
    } while (0)

#define da_delete(da, x) \
    do { \
        ptrdiff_t i; \
        assert(sizeof(*(x)) == sizeof(*(da)->items)); \
        i = ((x)-(da)->items)/sizeof(*(x)); \
        assert(i >= 0); \
        memcpy(&(da)->items[i], &(da)->items[i+1], sizeof(*(da)->items)*(--(da)->count - i)); \
    } while (0)

typedef struct {
    char *items;
    size_t count;
    size_t capacity;
} String_Builder;

typedef struct {
    const char *data;
    size_t count;
} String_View;

#define SV_Fmt "%.*s"
#define SV_Arg(sv) (int) sv.count, sv.data

int sv_eq_cstr(String_View sv, const char *cstr)
{
    size_t i;
    for (i = 0; i < sv.count; ++i) {
        if (sv.data[i] != *cstr++) return 0;
    }
    return *cstr == '\0';
}

String_View sv_from_parts(const char *data, size_t n)
{
    String_View sv;
    sv.data = data;
    sv.count = n;
    return sv;
}

String_View sv_from_cstr(const char *cstr)
{
    return sv_from_parts(cstr, strlen(cstr));
}

int sv_ends_with_cstr(String_View sv, const char *cstr)
{
    const size_t cstr_len = strlen(cstr);
    return cstr_len > sv.count ||
            !sv_eq_cstr(sv_from_parts(&sv.data[sv.count-cstr_len], cstr_len), cstr);
}

String_View sv_from_sb(const String_Builder *sb)
{
    return sv_from_parts(sb->items, sb->count);
}

String_View sv_chop(String_View *sv, size_t n)
{
    String_View chopped;
    if (n > sv->count) n = sv->count;
    chopped.data = sv->data;
    chopped.count = n;
    sv->data += n;
    sv->count -= n;

    return chopped;
}

String_View sv_chop_while(String_View *sv, int (*pred)(int))
{
    size_t i = 0;

    while (i < sv->count && pred(sv->data[i])) {
        i++;
    }
    return sv_chop(sv, i);
}

String_View sv_trim_right(String_View sv)
{
    size_t i = 0;

    while (sv.count - i > 1 && isspace(sv.data[sv.count - i - 1])) {
        ++i;
    }

    return sv_chop(&sv, sv.count - i);
}

String_View sv_trim_left(String_View sv)
{
    sv_chop_while(&sv, isspace);
    return sv;
}

String_View sv_trim(String_View sv)
{
    return sv_trim_left(sv_trim_right(sv));
}

int sv_eq(String_View a, String_View b)
{
    size_t i;
    if (a.count != b.count) return 0;

    for (i = 0; i < a.count; ++i) {
        if (a.data[i] != b.data[i]) return 0;
    }

    return 1;
}

String_View sv_chop_by_delim(String_View *sv, char delim)
{
    size_t i = 0;

    while (i < sv->count && sv->data[i] != delim) {
        ++i;
    }

    return sv_chop(sv, i);
}

String_View sv_chop_by_sv_delim(String_View *sv, String_View delim)
{
    size_t offset = 0;
    const size_t limit = sv->count - delim.count;
    while (offset < limit && !sv_eq(sv_from_parts(&sv->data[offset], delim.count), delim)) {
        offset++;
    }
    return sv_chop(sv, offset + delim.count);
}

String_View sv_chop_by_cstr_delim(String_View *sv, const char *cstr)
{
    return sv_chop_by_sv_delim(sv, sv_from_cstr(cstr));
}

typedef struct {
    int fd;

    char read_buf[512];
    char write_buf[512];

    /*
       read_avail - available data in buffer (without fetching)
       read_pos - pos from which bs_read() takes data
     */
    int read_avail, read_pos;
    /*
       write_avail - available data to write to buffer (without flushing)
       write_pos - position to which add data to buffer
     */
    int write_avail, write_pos;

    int error;
} BufStream;

int bs_fetch(BufStream *bs)
{
    int n;
    n = read(bs->fd, &bs->read_buf[bs->read_avail + bs->read_pos],
            sizeof(bs->read_buf) - bs->read_avail - bs->read_pos);
    if (n <= 0) {
        bs->error = (errno == EAGAIN || errno == EWOULDBLOCK)
            ? n == 0 : errno;
        return -1;
    }
    bs->read_avail += n;
    return 0;
}

int bs_read(BufStream *bs, void *to, int cnt)
{
    char *buf = to;
    int pos = 0;
    while (pos < cnt) {
        int avail = cnt - pos;
        if (avail > bs->read_avail) {
            avail = bs->read_avail;
        }
        if (!bs->read_avail) {
            if (bs_fetch(bs) < 0) return bs->error ? -1 : pos;
        }
        memcpy(&buf[pos], &bs->read_buf[bs->read_pos], avail);
        pos += avail;
        bs->read_pos = (bs->read_pos + avail) % sizeof(bs->read_buf);
        bs->read_avail -= avail;
    }
    return pos;
}

int read_until(BufStream *bs, String_Builder *sb, const char *until) {
    while (sv_ends_with_cstr(sv_from_sb(sb), until)) {
        char b;
        if (bs_read(bs, &b, sizeof(b)) < 0) return -1;
        da_append(sb, b);
        if (sb->count > 512000) {
            return -2;
        }
    }
    return 0;
}

typedef enum {
    HTTP_METH_GET
} HTTP_Method;

int http_method_from_sv(String_View sv)
{
    if (sv_eq_cstr(sv, "GET")) return HTTP_METH_GET;
    return -1;
}

typedef enum {
    HTTP_CONN_KEEPALIVE,
    HTTP_CONN_CLOSE
} HTTP_Connection;

int http_connection_from_sv(String_View sv)
{
    if (sv_eq_cstr(sv, "keep-alive")) return HTTP_CONN_KEEPALIVE;
    if (sv_eq_cstr(sv, "close")) return HTTP_CONN_CLOSE;
    return -1;
}

typedef struct {
    BufStream stream;
    bool dropped;
    time_t last_packet;
    enum {
        CST_REQUEST,
        CST_RESPONSING
    } state;
    struct pollfd *pfd;

    String_Builder request;
    String_Builder requested_path;
    String_View method;
    String_View connection;

    int afd;
} Connection;

typedef struct {
    Connection *items;
    size_t count;
    size_t capacity;
} Connections;

typedef struct {
    int sock;
    Connections connections;
    struct {
        struct pollfd *items;
        size_t count;
        size_t capacity;
    } polls;
} ServerCtx;

/* TODO: maybe make it sorted array to do binary search */
Connection *find_connection_by_pfd(Connections *cons, struct pollfd *pfd)
{
    size_t i;
    for (i = 0; i < cons->count; ++i) {
       if (cons->items[i].stream.fd == pfd->fd) {
           cons->items[i].pfd = pfd;
           return &cons->items[i];
       }
    }
    return NULL;
}

int ishex(int c)
{
    return ('0' <= c && c <= '9') ||
        ('a' <= c && c <= 'f');
}

int from_hexchars(String_View chars, int *v)
{
    size_t i;
    for (i = 0; i < chars.count; ++i) {
        char c = tolower(chars.data[i]);
        if (!ishex(c)) return -1;
        *v |= (c > '9' ? c - 'a' : c - '0');
    }
    return 0;
}

String_Builder http_decode_path(String_View path, int *err)
{
    String_Builder sb = {0};

    while (path.count) {
        int b;
        if (*path.data != '%') {
            da_append(&sb, *sv_chop(&path, 1).data);
            continue;
        }

        sv_chop(&path, 1);
        if (path.count < 2 ||
            from_hexchars(sv_chop(&path, 2), &b) < 0) {
            goto error;
        }
    }

    return sb;

error:
    free(sb.items);
    memset(&sb, 0, sizeof(sb));
    *err = 1;

    return sb;
}

int parse_http_first_line(Connection *c, String_View line)
{
    int i;
    for (i = 0; line.count; ++i) {
        int err = 0;
        String_View word = sv_chop_by_delim(&line, ' ');
        line = sv_trim_left(line);
        switch (i) {
            case 0: c->method = word; break;
            case 1:
                    assert(!c->requested_path.items);
                    c->requested_path = http_decode_path(word, &err);
                    break;
        }
        if (err) return -1;
    }
    return 0;
}

int parse_http_line(Connection *c, String_View line, int ln)
{
    String_View header, value;

    if (ln == 0) {
        return parse_http_first_line(c, line);
    }

    header = sv_chop_by_delim(&line, ':');
    sv_chop(&line, 1);
    value = sv_trim(line);
    if (value.count == 0) return -1;

    /* TODO: make a place for headers which needs to 
       be saved to make this place a simple loop */
    if (sv_eq_cstr(header, "Connection")) {
        c->connection = value;
    }
    return 0;
}

int parse_http_request(Connection *c)
{
    int linenumber;
    String_View whole = sv_trim(sv_from_sb(&c->request));

    for (linenumber = 0; whole.count; linenumber++) {
        String_View line = sv_chop_by_cstr_delim(&whole, "\r\n");
        line = sv_trim_right(line);
        if (parse_http_line(c, line, linenumber) < 0) return -1;
    }

    return 0;
}

int client_request(Connection *c)
{
    switch (read_until(&c->stream, &c->request, "\r\n\r\n")) {
    case -1: return 0;
    case -2:
        c->dropped = true;
        return -1;
    }

    if (parse_http_request(c) < 0) {
        c->dropped = true;
        return -1;
    }

    printf(SV_Fmt"\n", SV_Arg(c->method));
    printf(SV_Fmt"\n", SV_Arg(sv_from_sb(&c->requested_path)));
    printf(SV_Fmt"\n", SV_Arg(c->connection));

    c->pfd->events = POLLOUT;
    c->state = CST_RESPONSING;

    return 0;
}

int client_response(Connection *c)
{
    if (c->dropped) return -1;


    return 0;
}

void handle_output(Connection *c)
{
    (void) c;
    assert(0 && "Not implemented");
}

void delete_connection(ServerCtx *ctx, Connection *c)
{
    close(c->stream.fd);
    da_delete(&ctx->connections, c);
    da_delete(&ctx->polls, c->pfd);
    free(c->request.items);
    free(c->requested_path.items);
}

void handle_input(ServerCtx *ctx, Connection *c)
{
    switch (c->state) {
    case CST_REQUEST: {
        if (client_request(c) < 0) {
            delete_connection(ctx, c);
        }
    } break;
    case CST_RESPONSING: {
        if (client_response(c) < 0) {
            delete_connection(ctx, c);
        }
    } break;
    default: assert(0 && "unreachable");
    }
}

Connection new_connection(int fd)
{
    Connection c = {0};
    c.stream.fd = fd;
    c.last_packet = time(NULL);
    return c;
}

void handle_server(ServerCtx *ctx)
{
    int newsock, n;
    size_t i;
    struct sockaddr_in inaddr;
    int inaddr_len = sizeof(inaddr);
    n = poll(ctx->polls.items, ctx->polls.count, -1);
    for (i = 0; i < ctx->polls.count && n; ++i) {
        struct pollfd *cpfd = &ctx->polls.items[i];
        if (!cpfd->revents) continue;
        n--;
        if (cpfd->fd == ctx->sock) {
            int opt = 1;
            struct pollfd pfd;
            newsock = accept(ctx->sock, (struct sockaddr*)&inaddr, (socklen_t*)&inaddr_len);
            ioctl(newsock, FIONBIO, &opt);
            pfd.fd = newsock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            da_append(&ctx->polls, pfd);
            da_append(&ctx->connections, new_connection(newsock));
            continue;
        }
        if (cpfd->revents & POLLIN) {
            Connection *c = find_connection_by_pfd(&ctx->connections, cpfd);
            handle_input(ctx, c);
        }
        if (cpfd->revents & POLLOUT) {
            Connection *c = find_connection_by_pfd(&ctx->connections, cpfd);
            handle_output(c);
        }
    }
}

const char *shift_args(int *argc, char ***argv)
{
    if (!*argc) return 0;
    return (*argc)--, *(*argv)++;
}

int main(int argc, char **argv)
{
    int port = 8080;
    const char *program_name = shift_args(&argc, &argv);
    const char *arg = shift_args(&argc, &argv);
    struct sockaddr_in addr;
    ServerCtx ctx;

    (void) program_name;
    for (; arg; arg = shift_args(&argc, &argv)) {
        if (strcmp(arg, "-port") == 0) {
            if (argc == 0) {
                fprintf(stderr, "ERROR: port number expected\n");
                return 1;
            }
            port = atoi(shift_args(&argc, &argv));
        }
    }
    ctx.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx.sock < 0) {
        fprintf(stderr, "ERROR: could not create socket: %s\n",
                strerror(errno));
        return 1;
    }

    {
        int opt = 1;
        setsockopt(ctx.sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = 0;

    if (bind(ctx.sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ERROR: could not bind to port %d: %s\n",
                port,
                strerror(errno));
        return 1;
    }

    listen(ctx.sock, 15);
    {
        struct pollfd pfd;
        pfd.fd = ctx.sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
        da_append(&ctx.polls, pfd);
    }
    while (true) {
        handle_server(&ctx);
    }

    return 0;
}
