#include "../common.hpp"
#include <mutex>
#include <utility>

struct idkeeper {
	std::vector<std::pair<uint64_t, uint64_t> > ids;
	std::recursive_mutex mtx;
	std::string idfile;

	idkeeper() {
		ids.clear();
		ids.push_back(std::pair<uint64_t, uint64_t>(0, 0));
	}
	idkeeper(std::string file) : idfile(file) {
		idkeeper();
	}

	void load() {
		load(idfile);
	}
	void load(std::string file) {
		mtx.lock();
		std::vector<std::pair<uint64_t, uint64_t> > read;
		std::ifstream ifs(file);
		int count = 0;
		ifs >> count;
		if (count == 0) {
			idkeeper();
		} else {
			while (read.size() < count && !ifs.fail()) {
				uint64_t start, end;
				ifs >> start >> end;
				read.push_back(std::pair<uint64_t, uint64_t>(start, end));
			}
			if (!ifs.fail()) {
				ids = read;
			}
		}
		mtx.unlock();
	}

	void save() {
		save(idfile);
	}
	void save(std::string file) {
		mtx.lock();
		std::ofstream ofs(file);
		ofs << ids.size() << std::endl;
		for (auto p : ids) {
			ofs << p.first << " " << p.second << std::endl;
		}
		mtx.unlock();
	}

	std::vector<uint64_t> new_ids(uint64_t count) {
		mtx.lock();
		std::vector<uint64_t> ret;
		while (count > 0) {
			uint64_t start = 0, end = 0;

			if (ids.size() == 0) {
				start = 0;
				end = count;
				ids.push_back(std::pair<uint64_t, uint64_t>(0, count));
			} else if (ids.front().second - ids.front().first <= ids.back().second - ids.front().first && ids.back().second - ids.back().first <= ids.front().second - ids.back().first) {
				start = ids.back().second;
				end = ids.back().second + count;
				ids.back().second = end;
			} else if (ids.size() == 1) {
				start = ids.back().second;
				end = ids.front().first - 1;
				ids.back().second = end;
			} else {
				start = ids.back().second;
				end = ids.front().first;
				ids.back().second = ids.front().second;
				ids.erase(ids.begin());
			}

			for (uint64_t i = start; i != end; ++i) {
				ret.push_back(i);
				--count;
			}
		}
		save();
		mtx.unlock();
		return ret;
	}

	bool check_id(uint64_t id) {
		mtx.lock();
		bool ret = false;
		for (auto p : ids) {
			if (p.first <= p.second) {
				if (p.first <= id && id < p.second) {
					ret = true;
					break;
				}
			} else {
				if (id < p.second || p.first <= id) {
					ret = true;
					break;
				}
			}
		}
		mtx.unlock();
		return ret;
	}

	bool remove_id(uint64_t id) {
		mtx.lock();
		bool ret = false;
		std::pair<uint64_t, uint64_t> p;
		auto it = ids.begin();
		for (it = ids.begin(); it != ids.end(); ++it) {
			p = *it;
			if (p.first <= p.second) {
				if (p.first <= id && id < p.second) {
					ret = true;
					break;
				}
			} else {
				if (id < p.second || p.first <= id) {
					ret = true;
					break;
				}
			}
		}
		if (ret) {
			std::pair<uint64_t, uint64_t> lower(p.first, id);
			std::pair<uint64_t, uint64_t> upper(id + 1, p.second);
			if (lower.first == lower.second) {
				if (upper.first == upper.second) {
					ids.erase(it);
				} else {
					*it = upper;
				}
			} else {
				if (upper.first == upper.second) {
					*it = lower;
				} else {
					*it = upper;
					ids.insert(it, lower);
				}
			}
		}
		save();
		mtx.unlock();
		return ret;
	}
};
