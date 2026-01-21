# Net-Map

**Cross-platform Network Packet Analyzer with Web UI**

A lightweight, real-time packet sniffer with a modern Wireshark-style web interface. Built in C with libpcap/Npcap for high-performance packet capture.

![Net-Map Screenshot](logo.png)

## Features

### Packet Capture
- Real-time packet capture using libpcap/Npcap
- BPF (Berkeley Packet Filter) support
- Cross-platform: Windows and Linux

### Protocol Analysis
- **Layer 2**: Ethernet, ARP
- **Layer 3**: IPv4, ICMP
- **Layer 4**: TCP, UDP
- **Layer 7**: DNS, HTTP, HTTPS/TLS

### Web UI (Wireshark-style)
- **Packet List**: Sortable table with protocol coloring
- **Packet Details**: Expandable tree view for each protocol layer
- **Hex Dump**: Raw packet data in hex/ASCII view
- **Live Filtering**: Real-time display filter

### Statistics & Visualization
- **Protocol Distribution**: Pie chart with packet/byte counts
- **Endpoints**: Traffic statistics per IP address (Tx/Rx)
- **Ports**: Top ports by packet count with bar chart
- **Conversations**: Connection tracking between hosts
- **IO Graph**: Time-series traffic visualization

### Network Topology
- **D3.js Force Graph**: Visual network map
- **Node Types**: Local, Gateway, Remote, Broadcast
- **Interactive**: Drag, zoom, search, highlight

### Network Scanner
- **ARP Scan**: Local network host discovery
- **Ping Scan**: ICMP echo-based detection
- **TCP SYN Scan**: Port scanning (coming soon)

## Requirements

### Windows
- [Npcap](https://npcap.com/) - Install with "WinPcap API-compatible Mode" enabled
- [CMake](https://cmake.org/) 3.10+
- [Ninja](https://ninja-build.org/) (recommended) or Visual Studio
- Clang/LLVM or MSVC compiler

### Linux
```bash
sudo apt install libpcap-dev cmake ninja-build build-essential
```

## Build

```bash
# Clone repository
git clone https://github.com/hwkim3330/net-map.git
cd net-map

# Configure
cmake -B build -G Ninja

# Build
cmake --build build

# Run (requires admin/root privileges for packet capture)
./build/bin/net-map -l          # List available interfaces
./build/bin/net-map -i eth0     # Start capture on eth0
```

### Windows (PowerShell as Administrator)
```powershell
.\build\bin\net-map.exe -l
.\build\bin\net-map.exe -i "\Device\NPF_{GUID}"
```

## Usage

```
net-map [options]

Options:
  -i <interface>  Network interface to capture on
  -p <port>       Web server port (default: 8080)
  -f <filter>     BPF filter expression (e.g., "tcp port 80")
  -l              List available network interfaces
  -h              Show help message

Examples:
  net-map -i eth0                    # Capture all traffic on eth0
  net-map -i eth0 -f "tcp port 443"  # Capture only HTTPS traffic
  net-map -i eth0 -p 9090            # Use port 9090 for web UI
```

Open **http://localhost:8080** in your browser after starting.

## Project Structure

```
net-map/
├── src/
│   ├── core/              # Core functionality
│   │   ├── capture.c      # Packet capture (libpcap wrapper)
│   │   ├── parser.c       # Protocol parsing
│   │   ├── buffer.c       # Ring buffer for packets
│   │   └── scanner.c      # Network scanner
│   ├── platform/          # Platform-specific code
│   │   ├── windows.c      # Windows implementation
│   │   └── linux.c        # Linux implementation
│   ├── web/               # Web server
│   │   ├── server.c       # Mongoose HTTP server
│   │   ├── api.c          # REST API handlers
│   │   ├── websocket.c    # WebSocket for real-time updates
│   │   └── static/        # Web UI files
│   │       ├── index.html # Main HTML
│   │       ├── app.js     # JavaScript application
│   │       └── style.css  # Styles
│   └── main.c             # Entry point
├── include/               # Header files
│   ├── capture.h
│   ├── parser.h
│   ├── platform.h
│   └── scanner.h
├── lib/                   # Third-party libraries
│   ├── mongoose/          # Embedded web server
│   └── cJSON/             # JSON library
└── CMakeLists.txt
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Capture status and statistics |
| `/api/packets` | GET | Fetch captured packets |
| `/api/interfaces` | GET | List network interfaces |
| `/api/filter` | POST | Set BPF capture filter |
| `/api/control` | POST | Start/stop/clear capture |
| `/api/scan/start` | POST | Start network scan |
| `/api/scan/status` | GET | Get scan progress |
| `/api/scan/results` | GET | Get scan results |

## Dependencies

- [libpcap](https://www.tcpdump.org/) / [Npcap](https://npcap.com/) - Packet capture library
- [Mongoose](https://mongoose.ws/) - Embedded web server (MIT License)
- [cJSON](https://github.com/DaveGamble/cJSON) - JSON parser (MIT License)
- [D3.js](https://d3js.org/) - Network topology visualization (ISC License)
- [Chart.js](https://www.chartjs.org/) - Statistics charts (MIT License)

## Screenshots

### Packet Capture
Real-time packet list with protocol coloring and filtering.

### Protocol Statistics
Pie chart showing protocol distribution with detailed table.

### Network Topology
Interactive force-directed graph showing network connections.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Author

**hwkim3330**

---

*Built with C, libpcap, and modern web technologies.*
