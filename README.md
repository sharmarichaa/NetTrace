# NetTrace

A command-line network packet analyzer written in C++17. It reads `.pcap` capture files, decodes the packet headers by hand (no parsing libraries), prints traffic statistics, and flags suspicious patterns such as port scans and floods.

## Features

- Reads `.pcap` files (both byte orders, microsecond and nanosecond timestamps)
- Parses Ethernet (including 802.1Q VLAN tags), IPv4, TCP (with flags), UDP, ICMP and DNS (port 53)
- Labels ARP and IPv6 packets
- Protocol breakdown and top talkers by source IP
- Rule-based detection with tunable thresholds (see below)
- Exports every packet to `report.csv`
- Bounds-checked parsing: truncated, malformed or non-pcap files are reported, not crashed on

No machine learning and no external libraries. All header parsing and analysis logic is written from scratch.

## Detection rules

| Alert | Severity | Rule (default threshold) |
| --- | --- | --- |
| Port scan | HIGH | One source sends SYN-only packets to 15 or more distinct (IP, port) targets |
| SYN flood | HIGH | 100 or more SYN-only packets sent to one destination |
| ICMP flood | MEDIUM | 100 or more ICMP echo requests from one source |

Thresholds are constants at the top of `src/main.cpp`. These are simple heuristics: an alert is a pattern worth investigating, not proof of an attack.

## Build

Requires a C++17 compiler (g++) and CMake. On Windows, use MSYS2 UCRT64.

```
cmake -S . -B build
cmake --build build
```

## Usage

```
./build/nettrace data/http.cap           # first 20 packets + summary + alerts
./build/nettrace data/http.cap --all     # every packet
```

Example output (Wireshark's `http.cap` sample):

```
 No.  Time               Source                   Destination           Proto    Len  Info
   1  1084443427.311224  145.254.160.237:3372  -> 65.208.228.223:80     TCP       62  [SYN]
   2  1084443428.222534  65.208.228.223:80     -> 145.254.160.237:3372  TCP       62  [SYN,ACK]
   ...

== Summary ==
Packets: 43   Bytes: 25091

Protocols:
  TCP        41
  DNS        2

== Alerts ==
None found.
```

## Validation

- Packet counts, lengths, addresses and ports on `data/http.cap` were checked against Wireshark (43 packets, packet 1 is 62 bytes).
- Detection rules were tested on synthetic captures containing a port scan, a SYN flood and an ICMP flood.
- Edge cases tested: big-endian and nanosecond pcaps, VLAN-tagged frames, truncated files, pcapng input, and non-pcap files.

## Limitations

- Offline analysis of `.pcap` files only. No live capture yet, and `.pcapng` files must be converted first (Wireshark: File > Save As > pcap).
- Ethernet link type and IPv4 only. IPv6 packets are counted but not decoded.
- No TCP stream reassembly, and IP fragments are labelled but not reassembled.
- Only capture and analyze traffic on networks you own or are authorised to monitor.

## Roadmap

- Unit tests for the header parsers
- Live capture using Npcap/libpcap
- IPv6 parsing
- HTML report
