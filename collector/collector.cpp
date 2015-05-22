#include "../common.hpp"

struct config {
	std::string bankhost = "localhost";
	std::string bankport = "30021";
	std::string trustfile = "root.crt";
	std::string certfile = "self.crt";
	std::string keyfile = "self.key";
	std::string ecentfile = "ecents";
};
config conf;

std::vector<ecent> ecents;

void load_ecents(std::string file) {
	std::vector<ecent> ecs;
	std::ifstream ifs(file);
	int count;
	ifs >> count;
	while (ecs.size() < count) {
		ecent ec;
		ifs >> ec;
		ecs.push_back(ec);
	}
	if (!ifs.fail())
		ecents = ecs;
}

void save_ecents(std::string file) {
	std::ofstream ofs(file);
	ofs << ecents.size() << std::endl;
	for (auto ec : ecents) {
		ofs << ec;
	}
}

std::string do_request(SSL_CTX *ctx, std::string host, std::string port, std::string reqmsg) {
	std::string resmsg;

	int sfd = open_connect(host.c_str(), port.c_str());
	if (sfd < 0) {
		fprintf(stderr, "Failed to open_connect\n");
		return resmsg;
	}

	SSL *ssl;
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		fprintf(stderr, "Failed to SSL_new\n");
		close(sfd);
		return resmsg;
	}
	SSL_set_fd(ssl, sfd);

	try {
		if (SSL_connect(ssl) == -1) {
			ERR_print_errors_fp(stderr);
			throw "Failed to SSL_connect";
		}

		if (SSL_write(ssl, reqmsg.c_str(), reqmsg.length()) < 0) {
			throw "Failed to SSL_write";
		}

		while (true) {
			char buf[1024] = {'\0'};
			int len = SSL_read(ssl, buf, sizeof(buf));
			if (len < 0) {
				ERR_print_errors_fp(stderr);
				throw "Failed to SSL_read";
			}
			std::string buf_str(buf, len);
			size_t pos = buf_str.find_first_of(TERMCHAR);
			if (pos != std::string::npos) {
				resmsg.append(buf_str, 0, pos + 1);
				break;
			} else {
				resmsg.append(buf_str);
			}
		}
	} catch (const char* errmsg) {
		resmsg.clear();
		fprintf(stderr, "%s\n", errmsg);
		char* sslerr = (char*)malloc(strlen("ERROR ") + strlen(errmsg) + 16);
		sprintf(sslerr, "ERROR %s;", errmsg);
		SSL_write(ssl, sslerr, strlen(sslerr));
		free(sslerr);
	}

	SSL_free(ssl);
	close(sfd);

#ifdef DEBUG
	fprintf(stderr, "do_request():\nSENT:\n%s\nRECEIVED:\n%s\n", reqmsg.c_str(), resmsg.c_str());
#endif

	return resmsg;
}


int get_ecents(SSL_CTX *ctx, std::string host, std::string port, int count) {
	ecent_purchase_request req(count);
	std::stringstream sso;
	sso << req;
	std::string reqmsg = sso.str();

	std::string resmsg = do_request(ctx, host, port, reqmsg);

	if (resmsg.empty()) return -1;

	std::stringstream ssi(resmsg);
	ecent_purchase_response res;
	ssi >> res;
	if (ssi.fail()) return -1;
	count = res.ecents.size();
	for (auto ec : res.ecents) {
		ecents.push_back(ec);
	}
	save_ecents(conf.ecentfile);

	return count;
}

int check_ecent(SSL_CTX *ctx, std::string host, std::string port, ecent ec) {
	ecent_validate_request req(ec);
	std::stringstream sso;
	sso << req;
	std::string reqmsg = sso.str();

	std::string resmsg = do_request(ctx, host, port, reqmsg);

	if (resmsg.empty()) return -1;

	std::stringstream ssi(resmsg);
	ecent_validate_response res;
	ssi >> res;
	if (ssi.fail()) return -2;
	if (res.isvalid) {
		return 1;
	} else {
		return 0;
	}
}

int redeem_ecent(SSL_CTX *ctx, std::string host, std::string port, ecent ec) {
	ecent_redeem_request req(ec);
	std::stringstream sso;
	sso << req;
	std::string reqmsg = sso.str();

	std::string resmsg = do_request(ctx, host, port, reqmsg);

	if (resmsg.empty()) return -1;

	std::stringstream ssi(resmsg);
	ecent_redeem_response res;
	ssi >> res;
	if (ssi.fail()) return -2;
	if (res.isvalid) {
		return 1;
	} else {
		return 0;
	}
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

	load_ecents(conf.ecentfile);

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
			if (host == ".") host = conf.bankhost;
			if (port == ".") port = conf.bankport;
			count = get_ecents(ctx, host, port, count);
			std::cout << "Got " << count << " eCents" << std::endl;
		} else if (cmd == "ecent_count") {
			std::cout << "Currently have " << ecents.size() << " ecents" << std::endl;
		} else if (cmd == "ecent_list") {
			std::cout << "eCent ids: ";
			for (auto ec : ecents) {
				std::cout << ec.ecid << " ";
			}
			std::cout << std::endl;
		} else if (cmd == "check_ecent") {
			std::string host, port;
			uint64_t id;
			std::cin >> host >> port >> id;
			if (host == ".") host = conf.bankhost;
			if (port == ".") port = conf.bankport;
			if (ecents.size() < 1) {
				std::cout << "No ecent to validate" << std::endl;
			} else {
				ecent check = ecents.front();
				for (auto ec : ecents) {
					if (ec.ecid == id) {
						check = ec;
						break;
					}
				}
				int res = check_ecent(ctx, host, port, check);
				if (res == 1) {
					std::cout << "eCent id " << check.ecid << " is valid" << std::endl;
				} else if (res == 0) {
					std::cout << "eCent id " << check.ecid << " is INVALID" << std::endl;
				} else {
					std::cout << "Failed to validate eCent with error code " << res << std::endl;
				}
			}
		} else if (cmd == "redeem_ecent") {
			std::string host, port;
			uint64_t id;
			std::cin >> host >> port >> id;
			if (host == ".") host = conf.bankhost;
			if (port == ".") port = conf.bankport;
			if (ecents.size() < 1) {
				std::cout << "No ecent to redeem" << std::endl;
			} else {
				auto it = ecents.begin();
				for (it = ecents.begin(); it != ecents.end(); ++it) {
					if ((*it).ecid == id) {
						break;
					}
				}
				if (it == ecents.end()) it = ecents.begin();
				int res = redeem_ecent(ctx, host, port, (*it));
				if (res == 1) {
					std::cout << "eCent id " << (*it).ecid << " redeemed" << std::endl;
					ecents.erase(it);
					save_ecents(conf.ecentfile);
				} else if (res == 0) {
					std::cout << "eCent id " << (*it).ecid << " REJECTED" << std::endl;
				} else {
					std::cout << "Failed to redeem eCent with error code " << res << std::endl;
				}
			}
		} else {
			std::cout << "Unknown command. Valid commands:" << std::endl;
			std::cout << "get_ecents <host> <port> <count>" << std::endl;
			std::cout << "ecent_count" << std::endl;
			std::cout << "ecent_list" << std::endl;
			std::cout << "check_ecent <host> <port> <ecent id>" << std::endl;
			std::cout << "redeem_ecent <host> <port> <ecent id>" << std::endl;
		}
	}

	SSL_CTX_free(ctx);

	return 0;
}
