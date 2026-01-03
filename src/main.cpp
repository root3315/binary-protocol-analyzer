#include "protocol_parser.h"
#include "packet_analyzer.h"
#include "hexdump.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <getopt.h>

using namespace bpa;

void printVersion() {
    std::cout << "Binary Protocol Analyzer v1.0.0\n";
    std::cout << "A low-level binary protocol analyzer for reverse engineering\n";
    std::cout << "and debugging network traffic.\n";
}

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [OPTIONS] [FILE]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help           Show this help message\n";
    std::cout << "  -v, --version        Show version information\n";
    std::cout << "  -f, --format FORMAT  Output format: classic, compact, detailed, carray\n";
    std::cout << "  -e, --endian ENDIAN  Endianness: little, big (default: little)\n";
    std::cout << "  -p, --parse          Parse as network packet\n";
    std::cout << "  -s, --stats          Show statistics\n";
    std::cout << "  -a, --analyze        Full packet analysis\n";
    std::cout << "  -d, --diff FILE2     Compare with another file\n";
    std::cout << "  -n, --pattern PAT    Find hex pattern in data\n";
    std::cout << "  -c, --color          Enable colored output\n";
    std::cout << "  -i, --input STRING   Parse hex string directly\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program << " capture.pcap\n";
    std::cout << "  " << program << "-p -s capture.bin\n";
    std::cout << "  " << program << "-i \"48 65 6c 6c 6f 20 57 6f 72 6c 64\"\n";
    std::cout << "  " << program << "--diff file1.bin file2.bin\n";
}

std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }
    
    return buffer;
}

void demonstrateProtocolParsing() {
    std::cout << "=== Protocol Parsing Demo ===\n\n";
    
    std::vector<uint8_t> sample_data = {
        0x01, 0x02, 0x03, 0x04,
        0x00, 0x10,
        0x00, 0x00, 0x00, 0x20,
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00
    };
    
    ProtocolParser parser(Endianness::Little);
    
    uint32_t magic;
    uint16_t version;
    uint32_t length;
    std::string message;
    
    size_t offset = 0;
    
    auto result = parser.parseUint32(sample_data, offset, magic);
    if (result.success()) {
        std::cout << "Magic number: 0x" << std::hex << magic << std::dec << "\n";
        offset += 4;
    }
    
    result = parser.parseUint16(sample_data, offset, version);
    if (result.success()) {
        std::cout << "Version: " << version << "\n";
        offset += 2;
    }
    
    result = parser.parseUint32(sample_data, offset, length);
    if (result.success()) {
        std::cout << "Payload length: " << length << "\n";
        offset += 4;
    }
    
    result = parser.parseStringNullTerminated(sample_data, offset, message);
    if (result.success()) {
        std::cout << "Message: " << message << "\n";
    }
    
    std::cout << "\nBytes parsed: " << parser.getBytesParsed() << "\n";
    std::cout << "CRC32: 0x" << std::hex << ProtocolParser::calculateCRC32(sample_data) 
              << std::dec << "\n";
}

void demonstratePacketAnalysis() {
    std::cout << "\n=== Packet Analysis Demo ===\n\n";
    
    std::vector<uint8_t> ethernet_packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
        0x00, 0x50, 0x1f, 0x90,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    PacketAnalyzer analyzer;
    analyzer.analyze(ethernet_packet);
    
    const auto& packets = analyzer.getPackets();
    if (!packets.empty()) {
        const auto& pkt = packets[0];
        std::cout << "Packet Description: " << pkt.description << "\n";
        std::cout << "Total size: " << pkt.total_size << " bytes\n";
        std::cout << "Header size: " << pkt.header_size << " bytes\n";
        
        if (pkt.has_eth) {
            std::cout << "\nEthernet Header:\n";
            std::cout << "  Source MAC: " << pkt.eth_header.srcMacString() << "\n";
            std::cout << "  Dest MAC:   " << pkt.eth_header.destMacString() << "\n";
            std::cout << "  EtherType:  0x" << std::hex << pkt.eth_header.ether_type 
                      << std::dec << "\n";
        }
        
        if (pkt.has_ipv4) {
            std::cout << "\nIPv4 Header:\n";
            std::cout << "  Version:    " << static_cast<int>(pkt.ipv4_header.version) << "\n";
            std::cout << "  IHL:        " << static_cast<int>(pkt.ipv4_header.ihl) << "\n";
            std::cout << "  TTL:        " << static_cast<int>(pkt.ipv4_header.ttl) << "\n";
            std::cout << "  Protocol:   " << static_cast<int>(pkt.ipv4_header.protocol) << "\n";
            std::cout << "  Source:     " << pkt.ipv4_header.srcAddrString() << "\n";
            std::cout << "  Dest:       " << pkt.ipv4_header.destAddrString() << "\n";
        }
        
        if (pkt.has_tcp) {
            std::cout << "\nTCP Header:\n";
            std::cout << "  Source Port: " << pkt.tcp_header.src_port << "\n";
            std::cout << "  Dest Port:   " << pkt.tcp_header.dest_port << "\n";
            std::cout << "  Seq Num:     " << pkt.tcp_header.seq_num << "\n";
            std::cout << "  Ack Num:     " << pkt.tcp_header.ack_num << "\n";
            std::cout << "  Flags:       ";
            if (pkt.tcp_header.flagSyn()) std::cout << "SYN ";
            if (pkt.tcp_header.flagAck()) std::cout << "ACK ";
            if (pkt.tcp_header.flagFin()) std::cout << "FIN ";
            if (pkt.tcp_header.flagRst()) std::cout << "RST ";
            if (pkt.tcp_header.flagPsh()) std::cout << "PSH ";
            std::cout << "\n";
        }
    }
    
    std::cout << "\n" << analyzer.generateReport();
}

void demonstrateHexDump(const std::vector<uint8_t>& data, HexDumpFormat format, bool color) {
    std::cout << "\n=== Hex Dump ===\n\n";
    
    HexDumpOptions options;
    options.format = format;
    options.show_ascii = true;
    options.show_offset = true;
    options.color_output = color;
    
    HexDumper dumper(options);
    std::cout << dumper.dump(data);
}

void demonstratePatternFinding(const std::vector<uint8_t>& data) {
    std::cout << "\n=== Pattern Analysis ===\n\n";
    
    auto null_regions = PatternFinder::findNullRegions(data, 4);
    if (!null_regions.empty()) {
        std::cout << "Null regions (4+ bytes):\n";
        for (const auto& region : null_regions) {
            std::cout << "  Offset 0x" << std::hex << region.offset << std::dec 
                      << " (" << region.pattern.size() << " bytes)\n";
        }
    } else {
        std::cout << "No significant null regions found.\n";
    }
    
    std::cout << "\nCRC32: 0x" << std::hex << ProtocolParser::calculateCRC32(data) 
              << std::dec << "\n";
    std::cout << "CRC16: 0x" << std::hex << ProtocolParser::calculateCRC16(data) 
              << std::dec << "\n";
}

void demonstrateFileDiff(const std::string& file1, const std::string& file2) {
    auto data1 = readFile(file1);
    auto data2 = readFile(file2);
    
    std::cout << BinaryDiff::diffReport(data1, data2);
}

void demonstrateHexStringParsing(const std::string& hex_input) {
    std::cout << "\n=== Hex String Parsing ===\n\n";
    
    auto data = ProtocolParser::hexStringToBytes(hex_input);
    
    std::cout << "Input: " << hex_input << "\n";
    std::cout << "Parsed bytes: " << data.size() << "\n";
    std::cout << "Hex output: " << ProtocolParser::bytesToHexString(data) << "\n";
    std::cout << "ASCII: " << HexDumper::toAscii(data) << "\n";
    
    HexDumpOptions options;
    options.format = HexDumpFormat::Classic;
    options.show_ascii = true;
    HexDumper dumper(options);
    std::cout << "\n" << dumper.dump(data);
}

int main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"help",     no_argument,       nullptr, 'h'},
        {"version",  no_argument,       nullptr, 'v'},
        {"format",   required_argument, nullptr, 'f'},
        {"endian",   required_argument, nullptr, 'e'},
        {"parse",    no_argument,       nullptr, 'p'},
        {"stats",    no_argument,       nullptr, 's'},
        {"analyze",  no_argument,       nullptr, 'a'},
        {"diff",     required_argument, nullptr, 'd'},
        {"pattern",  required_argument, nullptr, 'n'},
        {"color",    no_argument,       nullptr, 'c'},
        {"input",    required_argument, nullptr, 'i'},
        {nullptr,    0,                 nullptr, 0}
    };
    
    HexDumpFormat format = HexDumpFormat::Classic;
    Endianness endian = Endianness::Little;
    bool parse_packets = false;
    bool show_stats = false;
    bool full_analyze = false;
    bool color_output = false;
    std::string diff_file;
    std::string pattern;
    std::string hex_input;
    std::string input_file;
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "hvf:e:psad:n:ci:", 
                              long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 'v':
                printVersion();
                return 0;
            case 'f':
                if (std::strcmp(optarg, "classic") == 0) {
                    format = HexDumpFormat::Classic;
                } else if (std::strcmp(optarg, "compact") == 0) {
                    format = HexDumpFormat::Compact;
                } else if (std::strcmp(optarg, "detailed") == 0) {
                    format = HexDumpFormat::Detailed;
                } else if (std::strcmp(optarg, "carray") == 0) {
                    format = HexDumpFormat::CArray;
                } else {
                    std::cerr << "Unknown format: " << optarg << "\n";
                    return 1;
                }
                break;
            case 'e':
                if (std::strcmp(optarg, "little") == 0) {
                    endian = Endianness::Little;
                } else if (std::strcmp(optarg, "big") == 0) {
                    endian = Endianness::Big;
                } else {
                    std::cerr << "Unknown endianness: " << optarg << "\n";
                    return 1;
                }
                break;
            case 'p':
                parse_packets = true;
                break;
            case 's':
                show_stats = true;
                break;
            case 'a':
                full_analyze = true;
                break;
            case 'd':
                diff_file = optarg;
                break;
            case 'n':
                pattern = optarg;
                break;
            case 'c':
                color_output = true;
                break;
            case 'i':
                hex_input = optarg;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    if (optind < argc) {
        input_file = argv[optind];
    }
    
    if (!hex_input.empty()) {
        demonstrateHexStringParsing(hex_input);
        return 0;
    }
    
    if (!diff_file.empty()) {
        if (input_file.empty()) {
            std::cerr << "Error: Need two files for diff comparison\n";
            return 1;
        }
        demonstrateFileDiff(input_file, diff_file);
        return 0;
    }
    
    if (input_file.empty()) {
        std::cout << "No input file specified. Running demo mode.\n\n";
        demonstrateProtocolParsing();
        demonstratePacketAnalysis();
        
        std::vector<uint8_t> demo_data = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57,
            0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00, 0x00, 0x00
        };
        demonstrateHexDump(demo_data, format, color_output);
        demonstratePatternFinding(demo_data);
        return 0;
    }
    
    try {
        auto data = readFile(input_file);
        
        std::cout << "File: " << input_file << "\n";
        std::cout << "Size: " << data.size() << " bytes\n\n";
        
        if (full_analyze || parse_packets) {
            PacketAnalyzer analyzer;
            analyzer.analyze(data);
            
            if (show_stats) {
                std::cout << analyzer.generateReport();
                std::cout << "\n" << analyzer.getPortDistribution();
            }
            
            const auto& packets = analyzer.getPackets();
            for (size_t i = 0; i < packets.size() && i < 5; ++i) {
                std::cout << "\nPacket " << (i + 1) << ": " << packets[i].description << "\n";
            }
        }
        
        if (!pattern.empty()) {
            auto matches = PatternFinder::findHex(data, pattern);
            std::cout << "\nPattern '" << pattern << "' found " << matches.size() 
                      << " time(s):\n";
            for (const auto& match : matches) {
                std::cout << "  Offset: 0x" << std::hex << match.offset << std::dec << "\n";
            }
        }
        
        if (!full_analyze && !parse_packets) {
            demonstrateHexDump(data, format, color_output);
            demonstratePatternFinding(data);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
