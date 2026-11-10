// NetTrace - a small pcap packet analyzer (C++17, no external libraries)
// Usage: nettrace <file.pcap> [--all]
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

using Bytes = std::vector<uint8_t>;

// ---- detection thresholds (change these to tune the rules) ----
const size_t SCAN_PORT_LIMIT = 15;   // distinct SYN targets from one source
const int SYN_FLOOD_LIMIT = 100;     // SYN-only packets toward one destination IP:port
const int ICMP_FLOOD_LIMIT = 100;    // ICMP echo requests from one source

// ---- helpers: network byte order (big-endian) ----
static uint16_t be16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint32_t swap32(uint32_t v) {
    return ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) |
           ((v >> 8) & 0xff00u) | (v >> 24);
}

static std::string ipStr(const uint8_t* p) {
    char b[16];
    std::snprintf(b, sizeof b, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return b;
}

// ---- one parsed packet ----
struct Pkt {
    int no = 0;
    uint32_t sec = 0, usec = 0, len = 0;
    std::string proto = "Other";
    std::string src, dst;           // empty when the packet has no IPv4 header
    int sport = 0, dport = 0;
    int tcpFlags = -1;              // -1 = not TCP
    int icmpType = -1;              // -1 = not ICMP
};

static std::string flagStr(int f) {
    std::string s;
    if (f & 0x02) s += "SYN,";
    if (f & 0x10) s += "ACK,";
    if (f & 0x01) s += "FIN,";
    if (f & 0x04) s += "RST,";
    if (f & 0x08) s += "PSH,";
    if (f & 0x20) s += "URG,";
    if (s.empty()) return "";
    s.pop_back();
    return "[" + s + "]";
}

// Parses Ethernet -> IPv4 -> TCP/UDP/ICMP. Never reads past the buffer.
static void parsePacket(const Bytes& d, Pkt& k) {
    if (d.size() < 14) { k.proto = "Truncated"; return; }

    size_t off = 14;
    uint16_t etherType = be16(&d[12]);
    if (etherType == 0x8100 && d.size() >= 18) {   // VLAN tag
        etherType = be16(&d[16]);
        off = 18;
    }

    if (etherType == 0x0806) { k.proto = "ARP"; return; }
    if (etherType == 0x86dd) { k.proto = "IPv6"; return; }
    if (etherType != 0x0800) { k.proto = "Other"; return; }

    if (d.size() < off + 20) { k.proto = "Truncated"; return; }
    size_t ihl = (size_t)(d[off] & 0x0f) * 4;
    if ((d[off] >> 4) != 4 || ihl < 20 || d.size() < off + ihl) {
        k.proto = "Malformed";
        return;
    }

    uint8_t ipProto = d[off + 9];
    k.src = ipStr(&d[off + 12]);
    k.dst = ipStr(&d[off + 16]);
    size_t l4 = off + ihl;

    bool isFragment = (be16(&d[off + 6]) & 0x1fff) != 0;
    if (isFragment) { k.proto = "IPv4-frag"; return; }

    if (ipProto == 6) {                              // TCP
        k.proto = "TCP";
        if (d.size() < l4 + 14) { k.proto = "TCP-trunc"; return; }
        k.sport = be16(&d[l4]);
        k.dport = be16(&d[l4 + 2]);
        k.tcpFlags = d[l4 + 13];
    } else if (ipProto == 17) {                      // UDP
        k.proto = "UDP";
        if (d.size() < l4 + 8) { k.proto = "UDP-trunc"; return; }
        k.sport = be16(&d[l4]);
        k.dport = be16(&d[l4 + 2]);
        if (k.sport == 53 || k.dport == 53) k.proto = "DNS";
    } else if (ipProto == 1) {                       // ICMP
        k.proto = "ICMP";
        if (d.size() < l4 + 2) { k.proto = "ICMP-trunc"; return; }
        k.icmpType = d[l4];
    } else {
        k.proto = "IP-proto-" + std::to_string(ipProto);
    }
}

static std::string endpoint(const Pkt& k, bool isSrc) {
    const std::string& ip = isSrc ? k.src : k.dst;
    int port = isSrc ? k.sport : k.dport;
    if (ip.empty()) return "-";
    if (port == 0) return ip;
    return ip + ":" + std::to_string(port);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: nettrace <file.pcap> [--all]\n";
        return 1;
    }
    bool showAll = (argc > 2 && std::string(argv[2]) == "--all");

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::cout << "Cannot open file: " << argv[1] << "\n"; return 1; }

    // ---- global header (24 bytes) ----
    uint8_t gh[24];
    file.read(reinterpret_cast<char*>(gh), 24);
    if (file.gcount() < 24) { std::cout << "File too small to be a pcap\n"; return 1; }

    uint32_t magic;
    std::memcpy(&magic, gh, 4);
    bool swapped = false, nano = false;
    if (magic == 0xa1b2c3d4u)      { }
    else if (magic == 0xd4c3b2a1u) { swapped = true; }
    else if (magic == 0xa1b23c4du) { nano = true; }
    else if (magic == 0x4d3cb2a1u) { swapped = true; nano = true; }
    else if (magic == 0x0a0d0d0au) {
        std::cout << "This is a pcapng file. Open it in Wireshark and use "
                     "File > Save As > pcap, then try again.\n";
        return 1;
    } else {
        std::cout << "Not a pcap file (unknown magic number)\n";
        return 1;
    }

    auto rd32 = [&](const uint8_t* p) {
        uint32_t v;
        std::memcpy(&v, p, 4);
        return swapped ? swap32(v) : v;
    };

    uint32_t snaplen = rd32(gh + 16);
    uint32_t linkType = rd32(gh + 20);
    if (linkType != 1) {
        std::cout << "Only Ethernet captures (link type 1) are supported. This file has type "
                  << linkType << ".\n";
        return 1;
    }
    std::printf("File: %s  (Ethernet, snaplen %u, %s timestamps)\n\n",
                argv[1], snaplen, nano ? "nanosecond" : "microsecond");

    std::ofstream csv("report.csv");
    csv << "no,time,src,dst,proto,src_port,dst_port,length\n";

    // ---- statistics ----
    std::map<std::string, int> protoCount;
    std::map<std::string, int> pktsBySrc;
    std::map<std::string, uint64_t> bytesBySrc;
    std::map<std::string, std::set<std::pair<std::string, int>>> synTargets;
    std::map<std::pair<std::string, int>, int> synToTarget;  // (dst ip, dst port)
    std::map<std::string, int> echoBySrc;
    uint64_t totalBytes = 0;
    int count = 0;

    std::printf("%4s  %-17s  %-21s    %-21s %-6s %5s  %s\n",
                "No.", "Time", "Source", "Destination", "Proto", "Len", "Info");

    // ---- packet loop ----
    uint8_t rh[16];
    while (file.read(reinterpret_cast<char*>(rh), 16)) {
        Pkt k;
        k.no = ++count;
        k.sec = rd32(rh);
        k.usec = rd32(rh + 4);
        if (nano) k.usec /= 1000;
        uint32_t inclLen = rd32(rh + 8);
        k.len = rd32(rh + 12);

        if (inclLen > (1u << 24)) {
            std::printf("Packet %d has a corrupt length, stopping.\n", count);
            --count;
            break;
        }
        Bytes data(inclLen);
        file.read(reinterpret_cast<char*>(data.data()), inclLen);
        if ((uint32_t)file.gcount() < inclLen) {
            std::printf("File ends in the middle of packet %d, stopping.\n", count);
            --count;
            break;
        }

        parsePacket(data, k);
        totalBytes += k.len;
        protoCount[k.proto]++;

        if (!k.src.empty()) {
            pktsBySrc[k.src]++;
            bytesBySrc[k.src] += k.len;
        }
        bool synOnly = k.tcpFlags >= 0 && (k.tcpFlags & 0x02) && !(k.tcpFlags & 0x10);
        if (synOnly) {
            synTargets[k.src].insert({k.dst, k.dport});
            synToTarget[{k.dst, k.dport}]++;
        }
        if (k.icmpType == 8) echoBySrc[k.src]++;

        char tbuf[32];
        std::snprintf(tbuf, sizeof tbuf, "%u.%06u", k.sec, k.usec);
        csv << k.no << ',' << tbuf << ',' << k.src << ',' << k.dst << ','
            << k.proto << ',' << k.sport << ',' << k.dport << ',' << k.len << '\n';

        if (showAll || count <= 20) {
            std::string info = k.tcpFlags >= 0 ? flagStr(k.tcpFlags) : "";
            if (k.icmpType >= 0) info = "type " + std::to_string(k.icmpType);
            std::printf("%4d  %u.%06u  %-21s -> %-21s %-6s %5u  %s\n", k.no, k.sec,
                        k.usec, endpoint(k, true).c_str(), endpoint(k, false).c_str(),
                        k.proto.c_str(), k.len, info.c_str());
        }
    }
    if (!showAll && count > 20)
        std::printf("... (%d more packets, use --all to show every packet)\n", count - 20);

    // ---- summary ----
    std::printf("\n== Summary ==\nPackets: %d   Bytes: %llu\n", count,
                (unsigned long long)totalBytes);

    std::printf("\nProtocols:\n");
    std::vector<std::pair<std::string, int>> protos(protoCount.begin(), protoCount.end());
    std::sort(protos.begin(), protos.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    for (auto& p : protos) std::printf("  %-10s %d\n", p.first.c_str(), p.second);

    std::printf("\nTop talkers (by source IP):\n");
    std::vector<std::pair<std::string, int>> talkers(pktsBySrc.begin(), pktsBySrc.end());
    std::sort(talkers.begin(), talkers.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    for (size_t i = 0; i < talkers.size() && i < 5; i++)
        std::printf("  %-16s %d packets, %llu bytes\n", talkers[i].first.c_str(),
                    talkers[i].second, (unsigned long long)bytesBySrc[talkers[i].first]);

    // ---- detection ----
    std::printf("\n== Alerts ==\n");
    int alerts = 0;
    for (auto& s : synTargets)
        if (s.second.size() >= SCAN_PORT_LIMIT) {
            std::printf("[HIGH]   Possible port scan: %s sent SYNs to %zu different targets\n",
                        s.first.c_str(), s.second.size());
            alerts++;
        }
    for (auto& s : synToTarget)
        if (s.second >= SYN_FLOOD_LIMIT) {
            std::printf("[HIGH]   Possible SYN flood: %d SYN packets sent to %s:%d\n",
                        s.second, s.first.first.c_str(), s.first.second);
            alerts++;
        }
    for (auto& s : echoBySrc)
        if (s.second >= ICMP_FLOOD_LIMIT) {
            std::printf("[MEDIUM] Possible ICMP flood: %d echo requests from %s\n",
                        s.second, s.first.c_str());
            alerts++;
        }
    if (alerts == 0) std::printf("None found.\n");

    std::printf("\nFull packet list saved to report.csv\n");
    return 0;
}
