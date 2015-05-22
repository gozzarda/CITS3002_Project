#include "../common.hpp"
#include <thread>
#include "idkeeper.cpp"

struct config {
	std::string port = "30021";
	int listen_queue_len = 32;
	std::string trustfile = "root.crt";
	std::string certfile = "self.crt";
	std::string keyfile = "self.key";
	std::string pubfile = "self.pub";
	std::string ecidfile = "ecids";
};
config conf;

idkeeper ecids;
EVP_PKEY *privkey;
EVP_PKEY *pubkey;

void handle_ecent_purchase_request(SSL* ssl, std::string imsg) {
	std::stringstream ssi(imsg);
	ecent_purchase_request req;
	ssi >> req;
	if (ssi.fail()) throw "Failed to parse eCent purchase request";
	std::vector<uint64_t> ids = ecids.new_ids(req.count);
	ecent_purchase_response res;
	for (auto id : ids) {
		res.ecents.push_back(ecent(id, privkey));
	}
	std::stringstream sso;
	sso << res;
	std::string omsg = sso.str();
	if (SSL_write(ssl, omsg.c_str(), omsg.length()) < 0) {
		fprintf(stderr, "Failed to send eCents, recovering...\n");
		for (auto ec : res.ecents) {
			ecids.remove_id(ec.ecid);
		}
	}
}

void handle_ecent_validate_request(SSL* ssl, std::string imsg) {
	std::stringstream ssi(imsg);
	ecent_validate_request req;
	ssi >> req;
	if (ssi.fail()) throw "Failed to parse eCent validation request";
	bool val = ecids.check_id(req.ec.ecid) && (req.ec.verify_sig(pubkey) == 1);
	ecent_validate_response res(val);
	std::stringstream sso;
	sso << res;
	std::string omsg = sso.str();
	if (SSL_write(ssl, omsg.c_str(), omsg.length()) < 0) {
		fprintf(stderr, "Failed to send eCent validation response\n");
	}
}

void handle_ecent_redeem_request(SSL* ssl, std::string imsg) {
	std::stringstream ssi(imsg);
	ecent_redeem_request req;
	ssi >> req;
	if (ssi.fail()) throw "Failed to parse eCent redemption request";
	bool val = ecids.check_id(req.ec.ecid) && (req.ec.verify_sig(pubkey) == 1);
	ecent_redeem_response res(val);
	std::stringstream sso;
	sso << res;
	std::string omsg = sso.str();
	if (SSL_write(ssl, omsg.c_str(), omsg.length()) < 0) {
		fprintf(stderr, "Failed to send eCent validation response\n");
	} else if (val) {
		ecids.remove_id(req.ec.ecid);
	}
}

void handle_request(SSL* ssl) {
	try {
		if (SSL_accept(ssl) == -1) {
			ERR_print_errors_fp(stderr);
		} else {
			X509* cert;
			cert = SSL_get_peer_certificate(ssl);
			std::string client_ou;
			if (cert != NULL) {
				char ou_buf[1024] = {'\0'};
				X509_NAME_get_text_by_NID(X509_get_subject_name(cert), OBJ_txt2nid("OU"), ou_buf, sizeof(ou_buf)-1);
				printf("Incoming connection from %s\n", ou_buf);
				client_ou = ou_buf;
			}
			X509_free(cert);

			std::string imsg;
			while (true) {
				char buf[1024] = {'\0'};
				int len = SSL_read(ssl, buf, sizeof(buf));
				if (len < 0) {
					ERR_print_errors_fp(stderr);
					throw "Failed to read message";
				}
				std::string buf_str(buf, len);
				size_t pos = buf_str.find_first_of(TERMCHAR);
				if (pos != std::string::npos) {
					imsg.append(buf_str, 0, pos+1);
					break;
				} else {
					imsg.append(buf_str);
				}
			}

			std::stringstream ssi(imsg);
			std::string msgtype;
			ssi >> msgtype;
			if (msgtype != "REQUEST") throw "Unsupported message type";
			int msgcode;
			ssi >> msgcode;
			ssi.seekg(0);

			printf("%s %d\n", msgtype.c_str(), msgcode);
			if (msgcode == ECENT_PURCHASE_REQUEST) {
				handle_ecent_purchase_request(ssl, imsg);
			} else if (msgcode == ECENT_VALIDATE_REQUEST) {
				handle_ecent_validate_request(ssl, imsg);
			} else if (msgcode == ECENT_REDEEM_REQUEST) {
				handle_ecent_redeem_request(ssl, imsg);
			} else {
				throw "Unsupported message code";
			}
		}
	} catch(const char* errmsg) {
		fprintf(stderr, "%s\n", errmsg);
		char* sslerr = (char*)malloc(strlen("ERROR ") + strlen(errmsg) + 16);
		sprintf(sslerr, "ERROR %s;", errmsg);
		SSL_write(ssl, sslerr, strlen(sslerr));
		free(sslerr);
	}

	int cfd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(cfd);
}

int main(int argc, char *argv[]) {
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	SSL_CTX *ctx = SSL_CTX_new(SSLv3_server_method());
	if (ctx == NULL) {
		fprintf(stderr, "Failed to initialize SSL context\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (load_certs(ctx, conf.trustfile.c_str(), conf.certfile.c_str(), conf.keyfile.c_str()) != 0) {
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	FILE *keyfp;
	keyfp = fopen(conf.keyfile.c_str(), "r");
	privkey = PEM_read_PrivateKey(keyfp, NULL, NULL, NULL);
	fclose(keyfp);
	if (privkey == NULL) {
		fprintf(stderr, "Failed to load private key\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}
	keyfp = fopen(conf.pubfile.c_str(), "r");
	pubkey = PEM_read_PUBKEY(keyfp, NULL, NULL, NULL);
	fclose(keyfp);
	if (pubkey == NULL) {
		fprintf(stderr, "Failed to load public key\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}

	int sfd = open_listen(conf.port.c_str(), conf.listen_queue_len);
	if (sfd < 0) {
		SSL_CTX_free(ctx);
		exit(EXIT_FAILURE);
	}

	ecids.idfile = conf.ecidfile;
	ecids.load();

	while (true) {
		int cfd = accept(sfd, NULL, NULL);
		SSL *ssl;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, cfd);
		handle_request(ssl);
	}

	close(sfd);
	SSL_CTX_free(ctx);

	return 0;
}
