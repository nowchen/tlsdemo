
#include	<string.h>

#include	<unistd.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>

#include	<openssl/bio.h>
#include	<openssl/err.h>
#include	<openssl/ssl.h>


void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ERR_load_BIO_strings();
}

SSL_CTX*
create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		perror("unable to create ssl context");
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	return ctx;
}

void
configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}
}

int 
create_listen(short port)
{
	int lis = -1;
	struct sockaddr_in addr;

	memset(&addr, '\0', sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	lis = socket(AF_INET, SOCK_STREAM, 0);
	if (lis < 0) {
		perror("unable to create listen socket");
		goto failed;
	}

	if (bind(lis, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		perror("unable to bind");
		goto failed;
	}

	if (listen(lis, 511) < 0) {
		perror("unable to bind");
		goto failed;
	}

	return lis;

failed:
	if (lis >= 0) {
		close(lis);
	}
	exit(-1);
}

int main(int argc, char **argv)
{
	int lis;
	SSL_CTX *ctx;

	init_openssl();

	ctx = create_context();

	configure_context(ctx);

	lis = create_listen(4433);

	while(1) {
		int client_fd;
		struct sockaddr_in client_addr;
		socklen_t len = sizeof(client_addr);

		SSL *ssl;

		char reply[] = "test\n";

		client_fd = accept(lis, (struct sockaddr*) &client_addr, &len);
		if (client_fd < 0) {
			perror("unable to accept");
			exit(-1);
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client_fd);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			goto close_client;
		}

		SSL_write(ssl, reply, strlen(reply));

		SSL_read(ssl, reply, strlen(reply));
		printf("read from client:%5s\n", reply);

close_client:
		SSL_accept(ssl);
		close(client_fd);
	}

	close(lis);

	SSL_CTX_free(ctx);
	//cleanup_openssl();
	
	return 0;
}
