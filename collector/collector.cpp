#include "../common.hpp"

struct config {
	std::string trustfile = "root.crt";
	std::string certfile = "self.crt";
	std::string keyfile = "self.key";
	std::string ecentfile = "ecents";
};
config conf;

std::vector<ecent> load_ecents() {
	std::vector<ecent> ecs;
	std::ifstream ifs(conf.ecentfile);
	int count;
	ifs >> count;
	while (ecs.size() < count) {
		ecent ec;
		ifs >> ec;
		ecs.push_back(ec);
	}
	return ecs;
}

void save_ecents(std::vector<ecent> ecs) {
	std::ofstream ofs(conf.ecentfile);
	ofs << ecs.size() << std::endl;
	for (auto ec : ecs) {
		ofs << ec;
	}
}

int get_ecents(SSL_CTX *ctx, std::string host, std::string port, int count) {
	int sfd = open_connect(host.c_str(), port.c_str());

	SSL *ssl;
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sfd);

	if (SSL_connect(ssl) == -1) {
		fprintf(stderr, "Failed to SSL_connect()\n");
		ERR_print_errors_fp(stderr);
		count = -1;
	} else {
		ecent_request req(count);
		std::stringstream sso;
		sso << req;
		std::string str = sso.str();
		SSL_write(ssl, str.c_str(), str.length());

		str.clear();
		while (true) {
			char buf[1024] = {'\0'};
			int len = SSL_read(ssl, buf, sizeof(buf));
			if (len < 0) {
				ERR_print_errors_fp(stderr);
				count = -1;
				break;
			}
			std::string buf_str(buf, len);
			size_t pos = buf_str.find_first_of(TERMCHAR);
			if (pos != std::string::npos) {
				str.append(buf_str, 0, pos + 1);
				break;
			} else {
				str.append(buf_str);
			}
		}

		if (count != -1) {
			std::stringstream ssi(str);
			ecent_response res;
			ssi >> res;
			if (ssi.fail()) count = -1;
			else {
				count = res.ecents.size();
				std::vector<ecent> ecs = load_ecents();
				for (auto ec : res.ecents) {
					ecs.push_back(ec);
				}
				save_ecents(ecs);
			}
		}
	}

	SSL_free(ssl);
	close(sfd);

	return count;
}

int main(int argc, char *argv[]) {
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx = SSL_CTX_new(SSLv3_client_method());
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

	bool cmd_loop = true;
	while (cmd_loop) {
		std::string cmd;
		std::cin >> cmd;
		if (cmd == "exit") {
			cmd_loop = false;
		} else if (cmd == "get_ecents") {
			std::string host, port;
			int count;
			std::cin >> host >> port >> count;
			count = get_ecents(ctx, host, port, count);
			std::cout << "Got " << count << " eCents" << std::endl;
		}
	}

	SSL_CTX_free(ctx);

	return 0;
}
