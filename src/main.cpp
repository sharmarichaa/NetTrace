#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstdio>

struct PcapGlobalHeader {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: nettrace <file.pcap>\n";
        return 1;
    }
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cout << "Cannot open file\n";
        return 1;
    }

    PcapGlobalHeader h;
    file.read(reinterpret_cast<char*>(&h), sizeof(h));

    int count = 0;
    PcapRecordHeader r;
    while (file.read(reinterpret_cast<char*>(&r), sizeof(r))) {
        count++;
        if (count <= 10) {
            std::printf("Packet %d: time=%u.%06u length=%u\n",
                        count, r.ts_sec, r.ts_usec, r.incl_len);
        }
        file.seekg(r.incl_len, std::ios::cur);
    }
    std::printf("Total packets: %d\n", count);
    return 0;
}
