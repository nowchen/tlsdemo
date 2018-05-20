//
// Created by chenwc on 5/20/18.
//

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#define HOST  "m.jd.com"

void
init_openssl_library()
{
    (void) SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static int
verify_callback(int pre_revify, X509_STORE_CTX *ctx)
{
    printf("verify callback get: %d vs %d and %p", pre_revify, X509_V_OK, ctx);

    return pre_revify;
}

static SSL_CTX*
init_ssl_ctx()
{
    SSL_CTX *ctx = NULL;
    long res = -1;

    ctx = SSL_CTX_new( SSLv23_method());
    if (ctx == NULL) {
        perror("new ssl ctx error");
        exit(-1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_verify_depth(ctx, 4);

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    res = SSL_CTX_load_verify_locations(ctx, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", NULL);
    if (res != 1) {
        perror("load verify locations failed");
        exit(-1);
    }

    return ctx;
}

static int
init_connect(const char * const hostname, short port)
{
    struct hostent *host;
    int res = -1;

    host = gethostbyname(hostname);
    if (host == NULL) {
        perror("gethostname failed");
        exit(-1);
    }
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = *(long*) host->h_addr_list[0];

    res = connect(client_fd, (struct sockaddr *) &addr, sizeof(addr));
    if (res == -1) {
        perror("connect failed");
        exit(-1);
    }

    return client_fd;
}

static SSL*
init_ssl(SSL_CTX *ctx, int client_fd)
{
    SSL *ssl = NULL;
    long res = -1;

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        perror("new ssl");
        exit(-1);
    }

    SSL_set_fd(ssl, client_fd);

    res = SSL_connect(ssl);
    if (res != 1) {
        perror("ssl connect failed");
        exit(-1);
    }

    return ssl;
}
int
main(int argc, char **argv)
{
    SSL_CTX *ctx = NULL;
    long res = 1;
    int client_fd = -1;
    SSL *ssl = NULL;

    init_openssl_library();

    ctx = init_ssl_ctx();

    client_fd = init_connect(HOST, 443);

    ssl  = init_ssl(ctx, client_fd);

    char http_msg[] = "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n";
    res = SSL_write(ssl, http_msg, sizeof(http_msg));
    if (res < 0) {
        perror("ssl write failed");
        exit(-1);
    }

    char buff[22281] = "";

    memset(buff, 0, sizeof(buff));
    res = SSL_read(ssl, buff, sizeof(buff));
    if (res < 0) {
        perror("ssl read failed");
        exit(-1);
    }

    printf("recv: %*s", res, buff);

    return 0;
}