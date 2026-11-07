# NetTrace

NetTrace is a network packet analyzer built in C++.

It captures network traffic, parses packet headers, and displays information about protocols, IP addresses, ports, packet sizes, and other network details.

The project is being developed to understand how network traffic works at the packet level and to build practical network security tooling from scratch.

## Features

- Live packet capture
- Ethernet frame parsing
- IPv4 packet parsing
- TCP packet parsing
- UDP packet parsing
- ICMP packet parsing
- Source and destination IP information
- Source and destination port information
- Packet size and timestamp
- Protocol statistics
- Packet filtering
- Suspicious traffic detection
- CSV export
- Capture history

## Technologies

- C++
- Npcap
- Qt
- SQLite
- CMake

## Planned Security Detection

NetTrace will use rule-based detection to identify patterns such as:

- Possible port scanning
- Repeated connection attempts
- Unusual ICMP traffic
- High packet rates
- Repeated connections to the same destination

No machine learning is used.

## Project Structure

```text
NetTrace/
├── src/
│   ├── capture/
│   ├── parser/
│   ├── analysis/
│   ├── detection/
│   └── main.cpp
├── include/
├── tests/
├── resources/
├── CMakeLists.txt
└── README.md
```

## Requirements

- Windows
- C++17 or later
- CMake
- Npcap
- Qt 6
- SQLite

## Building

Build instructions will be added as the project develops.

## Status

🚧 Work in progress



## Purpose

This project is mainly a hands-on implementation of network packet analysis and security monitoring using C++.

The goal is to understand the underlying networking concepts rather than relying on high-level packet analysis tools.
