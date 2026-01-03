# Binary Protocol Analyzer

A low-level binary protocol analyzer for reverse engineering and debugging network traffic.

## Features

- **Hex Dump**: Multiple output formats (classic, compact, detailed, C array)
- **Protocol Parsing**: Parse integers, floats, strings with configurable endianness
- **Packet Analysis**: Ethernet, IPv4, TCP, UDP header parsing
- **Pattern Finding**: Search for byte patterns, null regions, and hex sequences
- **Binary Diff**: Compare two binary files and identify differences
- **CRC Calculation**: CRC32 and CRC16 checksum computation

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.14 or higher
- Standard C library

## Installation

### Build from Source

```bash
mkdir build && cd build
cmake ..
make
```

### Install

```bash
sudo make install
```

## Usage

### Basic Usage

```bash
# Run demo mode (no input file)
./binary_protocol_analyzer

# View hex dump of a file
./binary_protocol_analyzer capture.bin

# Parse as network packet
./binary_protocol_analyzer -p capture.pcap

# Show statistics
./binary_protocol_analyzer -p -s capture.pcap

# Full packet analysis
./binary_protocol_analyzer -a capture.pcap
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version information |
| `-f, --format FORMAT` | Output format: classic, compact, detailed, carray |
| `-e, --endian ENDIAN` | Endianness: little, big (default: little) |
| `-p, --parse` | Parse as network packet |
| `-s, --stats` | Show statistics |
| `-a, --analyze` | Full packet analysis |
| `-d, --diff FILE2` | Compare with another file |
| `-n, --pattern PAT` | Find hex pattern in data |
| `-c, --color` | Enable colored output |
| `-i, --input STRING` | Parse hex string directly |

### Examples

```bash
# Parse a hex string
./binary_protocol_analyzer -i "48 65 6c 6c 6f 20 57 6f 72 6c 64"

# Compare two binary files
./binary_protocol_analyzer file1.bin -d file2.bin

# Find a pattern in data
./binary_protocol_analyzer -n "deadbeef" capture.bin

# Generate C array output
./binary_protocol_analyzer -f carray data.bin
```

## How It Works

### Protocol Parser

The `ProtocolParser` class provides methods to parse binary data into various types:

```cpp
ProtocolParser parser(Endianness::Little);

uint32_t magic;
parser.parseUint32(data, 0, magic);

float value;
parser.parseFloat(data, 4, value);

std::string str;
parser.parseStringNullTerminated(data, 8, str);
```

### Packet Analyzer

The `PacketAnalyzer` class parses network packet headers:

```cpp
PacketAnalyzer analyzer;
analyzer.analyze(packet_data);

const auto& packets = analyzer.getPackets();
for (const auto& pkt : packets) {
    if (pkt.has_ipv4) {
        std::cout << pkt.ipv4_header.srcAddrString() << " -> "
                  << pkt.ipv4_header.destAddrString() << "\n";
    }
}
```

### Hex Dumper

The `HexDumper` class provides multiple output formats:

```cpp
HexDumpOptions options;
options.format = HexDumpFormat::Classic;
options.show_ascii = true;

HexDumper dumper(options);
std::cout << dumper.dump(data);
```

### Pattern Finder

Find patterns in binary data:

```cpp
// Find a byte pattern
auto matches = PatternFinder::find(data, pattern);

// Find hex pattern
auto matches = PatternFinder::findHex(data, "deadbeef");

// Find null regions
auto regions = PatternFinder::findNullRegions(data, 16);
```

## Project Structure

```
binary-protocol-analyzer/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── src/
│   ├── main.cpp            # Main entry point
│   ├── protocol_parser.h   # Protocol parser header
│   ├── protocol_parser.cpp # Protocol parser implementation
│   ├── packet_analyzer.h   # Packet analyzer header
│   ├── packet_analyzer.cpp # Packet analyzer implementation
│   ├── hexdump.h           # Hex dump utilities header
│   └── hexdump.cpp         # Hex dump utilities implementation
└── tests/
    └── test_parser.cpp     # Unit tests
```

## Running Tests

```bash
cd build
cmake ..
make
ctest
```

Or run the test executable directly:

```bash
./build/test_parser
```

## Supported Protocols

- **Ethernet**: MAC addresses, EtherType
- **IPv4**: Version, IHL, TOS, Total Length, Identification, Flags, Fragment Offset, TTL, Protocol, Header Checksum, Source/Dest addresses
- **TCP**: Source/Dest ports, Sequence/Ack numbers, Data offset, Flags (SYN, ACK, FIN, RST, PSH), Window, Checksum, Urgent pointer
- **UDP**: Source/Dest ports, Length, Checksum

## CRC Algorithms

- **CRC32**: Standard CRC32 polynomial (0xEDB88320)
- **CRC16**: CRC16-IBM polynomial (0xA001)

## License

This project is provided as-is for educational and reverse engineering purposes.
