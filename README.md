# Net-Map

Cross-platform packet sniffer with web UI.

![Net-Map](icon.png)

## Features

- Cross-platform (Windows + Linux)
- Web-based UI (Wireshark-style)
- Real-time packet capture
- BPF filter support
- Protocol parsing (Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS, HTTP/S)

## Requirements

### Windows
- [Npcap](https://npcap.com/) (with WinPcap API compatibility mode)
- [CMake](https://cmake.org/) 3.10+
- [Ninja](https://ninja-build.org/) (recommended)
- LLVM/Clang or MSVC

### Linux
```bash
sudo apt install libpcap-dev cmake ninja-build build-essential
```

## Build

```bash
# Configure
cmake -B build -G Ninja

# Build
cmake --build build

# Run
./build/bin/net-map -l          # List interfaces
./build/bin/net-map -i eth0     # Capture on eth0
```

## Usage

```
net-map [options]
  -i <interface>  Network interface to capture on
  -p <port>       Web server port (default: 8080)
  -f <filter>     BPF filter expression
  -l              List available interfaces
  -h              Show help
```

Open http://localhost:8080 in your browser.

## Project Structure

```
net-map/
├── src/
│   ├── core/           # Packet capture & parsing
│   ├── platform/       # Platform-specific code
│   └── web/            # Web server & API
│       └── static/     # Web UI files
├── include/            # Header files
├── lib/                # Third-party libraries
└── CMakeLists.txt
```

## Dependencies

- [libpcap](https://www.tcpdump.org/) / [Npcap](https://npcap.com/) - Packet capture
- [Mongoose](https://mongoose.ws/) - Embedded web server
- [cJSON](https://github.com/DaveGamble/cJSON) - JSON library

## License

MIT
