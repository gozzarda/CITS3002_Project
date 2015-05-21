#include "common.hpp"

int load_certs(SSL_CTX *ctx, const char *trustfile, const char *certfile, const char *keyfile) {
	if (SSL_CTX_load_verify_locations(ctx, trustfile, NULL) != 1) {
		fprintf(stderr, "Failed to load trusted certificates\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, certfile) <= 0) {
		fprintf(stderr, "Failed to load certificate file\n");
		ERR_print_errors_fp(stderr);
		return -2;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load private key file\n");
		ERR_print_errors_fp(stderr);
		return -3;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Certificate and private key files do not match\n");
		return -4;
	}
	return 0;
}

int open_listen(const char* port, const int listen_queue_len) {
	int sfd;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *res;
	int gai_ret = getaddrinfo(NULL, port, &hints, &res);
	if (gai_ret != 0) {
		fprintf(stderr, "Failed to getaddrinfo()\n");
		fprintf(stderr, "%s\n", gai_strerror(gai_ret));
		return -1;
	}

	struct addrinfo *sai;
	for (sai = res; sai != NULL; sai = sai->ai_next) {
		sfd = socket(sai->ai_family, sai->ai_socktype, sai->ai_protocol);
		if (sfd == -1) continue;
		int bind_ret = bind(sfd, sai->ai_addr, sai->ai_addrlen);
		if (bind_ret == 0) break;
		else close(sfd);
	}
	if (sai == NULL) {
		fprintf(stderr, "Failed to bind()\n");
		return -2;
	}

	freeaddrinfo(res);

	if (listen(sfd, listen_queue_len) != 0) {
		fprintf(stderr, "Failed to listen()\n");
		return -3;
	}

	return sfd;
}

int open_connect(const char* host, const char* port) {
	int sfd;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *res;
	int gai_ret = getaddrinfo(host, port, &hints, &res);
	if (gai_ret != 0) {
		fprintf(stderr, "Failed to getaddrinfo()\n");
		fprintf(stderr, "%s\n", gai_strerror(gai_ret));
		return -1;
	}

	struct addrinfo *sai;
	for (sai = res; sai != NULL; sai = sai->ai_next) {
		sfd = socket(sai->ai_family, sai->ai_socktype, sai->ai_protocol);
		if (sfd == -1) continue;
		int conn_ret = connect(sfd, sai->ai_addr, sai->ai_addrlen);
		if (conn_ret == 0) break;
		else close(sfd);
	}
	if (sai == NULL) {
		fprintf(stderr, "Failed to connect()\n");
		return -2;
	}
	freeaddrinfo(res);

	return sfd;
}
