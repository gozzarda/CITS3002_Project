#include "common.hpp"

#define SALT_LEN 32

#define TERMCHAR ';'
#define REQSTR "REQUEST"
#define RESSTR "RESPONSE"

#define CODE_ECENT_REQUEST 100
#define CODE_ECENT_RESPONSE 101

typedef uint16_t code_t;
typedef unsigned char byte;

struct ecent {
	uint64_t ecid;
	std::vector<byte> salt;
	std::vector<byte> sign;
	ecent() {}
	ecent(uint64_t id, EVP_PKEY *pkey) : ecid(id) {
		std::vector<byte> body;
		uint64_t id_temp = ecid;
		for (int i = 0; i < sizeof(id); ++i) {
			body.push_back(static_cast<byte>(id_temp & 0xFF));
			id_temp >>= 8;
		}

		salt.resize(SALT_LEN);
		if (RAND_bytes(salt.data(), salt.size()) != 1) {
			fprintf(stderr, "Failed to generate salt for new eCent\n");
			throw -1;
		}

		body.insert(body.end(), salt.begin(), salt.end());

		EVP_MD_CTX md_ctx;
		EVP_SignInit(&md_ctx, EVP_sha1());
		if (EVP_SignUpdate(&md_ctx, body.data(), body.size()) != 1) {
			fprintf(stderr, "Failed to update signature for new eCent\n");
			ERR_print_errors_fp(stderr);
			throw -2;
		}
		sign.resize(EVP_PKEY_size(pkey));
		unsigned int sig_len;
		if (EVP_SignFinal(&md_ctx, sign.data(), &sig_len, pkey) != 1) {
			fprintf(stderr, "Failed to finalize signature for new eCent\n");
			ERR_print_errors_fp(stderr);
			throw -3;
		}
		sign.resize(sig_len);
	}
	friend std::ostream& operator<<(std::ostream& os, const ecent& ec) {
		os << ec.ecid << std::endl;
		os << ec.salt.size() << std::endl;
		for (auto b : ec.salt) {
			os << static_cast<int>(b) << " ";
		}
		os << std::endl;
		os << ec.sign.size() << std::endl;
		for (auto b : ec.sign) {
			os << static_cast<int>(b) << " ";
		}
		os << std::endl;
		return os;
	}
	friend std::istream& operator>>(std::istream& is, ecent& ec) {
		is >> ec.ecid;
		int salt_size;
		is >> salt_size;
		ec.salt.clear();
		while (ec.salt.size() < salt_size) {
			int b;
			is >> b;
			ec.salt.push_back(static_cast<byte>(b));
		}
		int sign_size;
		is >> sign_size;
		ec.sign.clear();
		while (ec.sign.size() < sign_size) {
			int b;
			is >> b;
			ec.sign.push_back(static_cast<byte>(b));
		}
		is >> std::ws;
		return is;
	}
	int verify_sig(EVP_PKEY *pkey) {
		std::vector<byte> body;
		auto id_temp = ecid;
		for (int i = 0; i < sizeof(id_temp); ++i) {
			body.push_back(static_cast<byte>(id_temp & 0xFF));
			id_temp >>= 8;
		}

		body.insert(body.end(), salt.begin(), salt.end());

		EVP_MD_CTX md_ctx;
		EVP_VerifyInit(&md_ctx, EVP_sha1());
		if (EVP_VerifyUpdate(&md_ctx, body.data(), body.size()) != 1) {
			return -1;
		}
		return EVP_VerifyFinal(&md_ctx, sign.data(), sign.size(), pkey);
	}
};

struct ecent_request {
	const code_t code = CODE_ECENT_REQUEST;
	uint32_t count;
	ecent_request() {}
	ecent_request(int count) : count(count) {}
	friend std::ostream& operator<<(std::ostream& os, const ecent_request& req) {
		os << REQSTR << " " << req.code << std::endl;
		os << req.count << std::endl;
		os << TERMCHAR << std::endl;
		return os;
	}
	friend std::istream& operator>>(std::istream& is, ecent_request& req) {
		std::string req_str;
		is >> req_str;
		if (req_str != REQSTR)
			is.setstate(std::ios::failbit);
		
		code_t incode;
		is >> incode;
		if (incode != req.code)
			is.setstate(std::ios::failbit);

		is >> req.count;

		char end_char;
		is >> end_char;
		if (end_char != TERMCHAR)
			is.setstate(std::ios::failbit);

		return is;
	}
};

struct ecent_response {
	const code_t code = CODE_ECENT_RESPONSE;
	std::vector<ecent> ecents;
	ecent_response() {}
	ecent_response(std::vector<ecent> ecs) : ecents(ecs) {}
	friend std::ostream& operator<<(std::ostream& os, const ecent_response& res) {
		os << RESSTR << " " << res.code << std::endl;
		os << res.ecents.size() << std::endl;
		for (auto ec : res.ecents)
			os << ec;
		os << TERMCHAR << std::endl;
		return os;
	}
	friend std::istream& operator>>(std::istream& is, ecent_response& res) {
		std::string res_str;
		is >> res_str;
		if (res_str != RESSTR)
			is.setstate(std::ios::failbit);
		
		code_t incode;
		is >> incode;
		if (incode != res.code)
			is.setstate(std::ios::failbit);

		uint32_t count;
		is >> count;
		res.ecents.clear();
		while (res.ecents.size() < count) {
			ecent ec;
			is >> ec;
			res.ecents.push_back(ec);
		}

		char end_char;
		is >> end_char;
		if (end_char != TERMCHAR)
			is.setstate(std::ios::failbit);

		return is;
	}
};
