#include "protocol_parser.h"
#include "packet_analyzer.h"
#include "hexdump.h"

#include <iostream>
#include <cassert>
#include <cmath>
#include <cstring>

using namespace bpa;

int tests_run = 0;
int tests_passed = 0;

#define TEST(name) void name()
#define RUN_TEST(name) do { \
    std::cout << "Running " << #name << "... "; \
    tests_run++; \
    try { \
        name(); \
        tests_passed++; \
        std::cout << "PASSED\n"; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << "\n"; \
    } \
} while(0)

#define ASSERT_TRUE(expr) do { if (!(expr)) throw std::runtime_error("Assertion failed: " #expr); } while(0)
#define ASSERT_FALSE(expr) do { if (expr) throw std::runtime_error("Assertion failed: !" #expr); } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b); } while(0)
#define ASSERT_NEAR(a, b, eps) do { if (std::fabs((a) - (b)) > (eps)) throw std::runtime_error("Assertion failed: " #a " ~= " #b); } while(0)

TEST(test_parse_uint8) {
    ProtocolParser parser;
    std::vector<uint8_t> data = {0x42, 0xFF, 0x00, 0x7F};
    
    uint8_t value;
    auto result = parser.parseUint8(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x42);
    
    result = parser.parseUint8(data, 1, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0xFF);
    
    result = parser.parseUint8(data, 2, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x00);
    
    result = parser.parseUint8(data, 4, value);
    ASSERT_FALSE(result.success());
}

TEST(test_parse_uint16_little_endian) {
    ProtocolParser parser(Endianness::Little);
    std::vector<uint8_t> data = {0x01, 0x02, 0xFF, 0xFF, 0x00, 0x00};
    
    uint16_t value;
    auto result = parser.parseUint16(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x0201);
    
    result = parser.parseUint16(data, 2, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0xFFFF);
    
    result = parser.parseUint16(data, 4, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x0000);
}

TEST(test_parse_uint16_big_endian) {
    ProtocolParser parser(Endianness::Big);
    std::vector<uint8_t> data = {0x01, 0x02, 0xFF, 0xFF, 0x00, 0x00};
    
    uint16_t value;
    auto result = parser.parseUint16(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x0102);
    
    result = parser.parseUint16(data, 2, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0xFFFF);
}

TEST(test_parse_uint32_little_endian) {
    ProtocolParser parser(Endianness::Little);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    
    uint32_t value;
    auto result = parser.parseUint32(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x04030201);
}

TEST(test_parse_uint32_big_endian) {
    ProtocolParser parser(Endianness::Big);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    
    uint32_t value;
    auto result = parser.parseUint32(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x01020304);
}

TEST(test_parse_uint64) {
    ProtocolParser parser(Endianness::Little);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    uint64_t value;
    auto result = parser.parseUint64(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, 0x0807060504030201ULL);
}

TEST(test_parse_integers_signed) {
    ProtocolParser parser(Endianness::Little);
    std::vector<uint8_t> data = {0xFF, 0xFF, 0xFF, 0xFF};
    
    int32_t value;
    auto result = parser.parseInt32(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, -1);
    
    data = {0x00, 0x00, 0x00, 0x80};
    result = parser.parseInt32(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, -2147483648);
}

TEST(test_parse_float) {
    ProtocolParser parser(Endianness::Little);
    
    float expected = 1.0f;
    std::vector<uint8_t> data(4);
    std::memcpy(data.data(), &expected, 4);
    
    float value;
    auto result = parser.parseFloat(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_NEAR(value, 1.0f, 0.0001f);
    
    expected = -2.5f;
    std::memcpy(data.data(), &expected, 4);
    result = parser.parseFloat(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_NEAR(value, -2.5f, 0.0001f);
}

TEST(test_parse_double) {
    ProtocolParser parser(Endianness::Little);
    
    double expected = 3.14159265359;
    std::vector<uint8_t> data(8);
    std::memcpy(data.data(), &expected, 8);
    
    double value;
    auto result = parser.parseDouble(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_NEAR(value, 3.14159265359, 0.0000001);
}

TEST(test_parse_string) {
    ProtocolParser parser;
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    
    std::string value;
    auto result = parser.parseString(data, 0, 5, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, "Hello");
    
    result = parser.parseString(data, 6, 5, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, "World");
}

TEST(test_parse_string_null_terminated) {
    ProtocolParser parser;
    std::vector<uint8_t> data = {'T', 'e', 's', 't', '\0', 'X', 'Y', 'Z', '\0'};
    
    std::string value;
    auto result = parser.parseStringNullTerminated(data, 0, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, "Test");
    
    result = parser.parseStringNullTerminated(data, 5, value);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(value, "XYZ");
}

TEST(test_hex_string_to_bytes) {
    auto bytes = ProtocolParser::hexStringToBytes("48656c6c6f");
    ASSERT_EQ(bytes.size(), 5);
    ASSERT_EQ(bytes[0], 'H');
    ASSERT_EQ(bytes[1], 'e');
    ASSERT_EQ(bytes[2], 'l');
    ASSERT_EQ(bytes[3], 'l');
    ASSERT_EQ(bytes[4], 'o');
    
    bytes = ProtocolParser::hexStringToBytes("48 65 6c 6c 6f");
    ASSERT_EQ(bytes.size(), 5);
    
    bytes = ProtocolParser::hexStringToBytes("ABCDEF");
    ASSERT_EQ(bytes.size(), 3);
    ASSERT_EQ(bytes[0], 0xAB);
    ASSERT_EQ(bytes[1], 0xCD);
    ASSERT_EQ(bytes[2], 0xEF);
    
    bytes = ProtocolParser::hexStringToBytes("f");
    ASSERT_EQ(bytes.size(), 1);
    ASSERT_EQ(bytes[0], 0x0F);
}

TEST(test_bytes_to_hex_string) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0xFF, 0x00};
    
    std::string hex = ProtocolParser::bytesToHexString(data, true);
    ASSERT_EQ(hex, "01 02 03 ff 00");
    
    hex = ProtocolParser::bytesToHexString(data, false);
    ASSERT_EQ(hex, "010203ff00");
}

TEST(test_crc32) {
    std::vector<uint8_t> data = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint32_t crc = ProtocolParser::calculateCRC32(data);
    ASSERT_EQ(crc, 0xCBF43926);
    
    std::vector<uint8_t> empty;
    crc = ProtocolParser::calculateCRC32(empty);
    ASSERT_EQ(crc, 0x00000000);
    
    std::vector<uint8_t> single = {0x00};
    crc = ProtocolParser::calculateCRC32(single);
    ASSERT_EQ(crc, 0xD202EF8D);
}

TEST(test_crc16) {
    std::vector<uint8_t> data = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint16_t crc = ProtocolParser::calculateCRC16(data);
    ASSERT_EQ(crc, 0x4B37);
}

TEST(test_protocol_definition) {
    ProtocolDefinition def;
    def.setName("TestProtocol");
    def.setMessageSize(10);
    def.addField("magic", 0, 4);
    def.addField("version", 4, 2);
    def.addField("length", 6, 4);
    
    ASSERT_EQ(def.getName(), "TestProtocol");
    ASSERT_EQ(def.getMessageSize(), 10);
    
    std::vector<uint8_t> data = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0x01, 0x00,
        0x10, 0x00, 0x00, 0x00
    };
    
    ProtocolParser parser(Endianness::Little);
    auto message = def.parse(data, parser);
    
    ASSERT_EQ(message.name, "TestProtocol");
    ASSERT_EQ(message.fields.size(), 3);
    ASSERT_EQ(message.fields[0].name, "magic");
    ASSERT_EQ(message.fields[1].name, "version");
    ASSERT_EQ(message.fields[2].name, "length");
}

TEST(test_packet_analyzer_ethernet) {
    std::vector<uint8_t> packet = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x08, 0x00
    };
    
    PacketAnalyzer analyzer;
    analyzer.analyze(packet);
    
    const auto& packets = analyzer.getPackets();
    ASSERT_EQ(packets.size(), 1);
    ASSERT_TRUE(packets[0].has_eth);
    ASSERT_EQ(packets[0].eth_header.ether_type, 0x0800);
}

TEST(test_packet_analyzer_ipv4_tcp) {
    std::vector<uint8_t> packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x7a, 0xb5,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
        0x00, 0x50, 0x1f, 0x90,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x12, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    PacketAnalyzer analyzer;
    analyzer.analyze(packet);

    const auto& packets = analyzer.getPackets();
    ASSERT_EQ(packets.size(), 1);
    ASSERT_TRUE(packets[0].has_ipv4);
    ASSERT_TRUE(packets[0].has_tcp);
    ASSERT_EQ(packets[0].ipv4_header.version, 4);
    ASSERT_EQ(packets[0].tcp_header.src_port, 80);
    ASSERT_EQ(packets[0].tcp_header.dest_port, 8080);
    ASSERT_TRUE(packets[0].tcp_header.flagSyn());
}

TEST(test_packet_analyzer_ipv6) {
    std::vector<uint8_t> packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x86, 0xDD,
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x06, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };

    PacketAnalyzer analyzer;
    analyzer.analyze(packet);

    const auto& packets = analyzer.getPackets();
    ASSERT_EQ(packets.size(), 1);
    ASSERT_TRUE(packets[0].has_ipv6);
    ASSERT_EQ(packets[0].ipv6_header.version, 6);
    ASSERT_EQ(packets[0].ipv6_header.payload_length, 0x0020);
    ASSERT_EQ(packets[0].ipv6_header.next_header, 0x06);
    ASSERT_EQ(packets[0].ipv6_header.hop_limit, 0x40);
    ASSERT_EQ(packets[0].ipv6_header.srcAddrString(), "2001:db8:0:0:0:0:0:1");
    ASSERT_EQ(packets[0].ipv6_header.destAddrString(), "2001:db8:0:0:0:0:0:2");
}

TEST(test_packet_analyzer_ipv6_tcp) {
    std::vector<uint8_t> packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x86, 0xDD,
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x06, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x1f, 0x90, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00,
        0xab, 0xcd, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    PacketAnalyzer analyzer;
    analyzer.analyze(packet);

    const auto& packets = analyzer.getPackets();
    ASSERT_EQ(packets.size(), 1);
    ASSERT_TRUE(packets[0].has_ipv6);
    ASSERT_TRUE(packets[0].has_tcp);
    ASSERT_EQ(packets[0].ipv6_header.version, 6);
    ASSERT_EQ(packets[0].ipv6_header.next_header, 0x06);
    ASSERT_EQ(packets[0].tcp_header.src_port, 8080);
    ASSERT_EQ(packets[0].tcp_header.dest_port, 80);
    ASSERT_TRUE(packets[0].tcp_header.flagSyn());
}

TEST(test_packet_analyzer_ipv6_udp) {
    std::vector<uint8_t> packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x86, 0xDD,
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x0c, 0x11, 0x40,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x35, 0x00, 0x35,
        0x00, 0x0c, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07
    };

    PacketAnalyzer analyzer;
    analyzer.analyze(packet);

    const auto& packets = analyzer.getPackets();
    ASSERT_EQ(packets.size(), 1);
    ASSERT_TRUE(packets[0].has_ipv6);
    ASSERT_TRUE(packets[0].has_udp);
    ASSERT_EQ(packets[0].ipv6_header.version, 6);
    ASSERT_EQ(packets[0].ipv6_header.next_header, 0x11);
    ASSERT_EQ(packets[0].udp_header.src_port, 53);
    ASSERT_EQ(packets[0].udp_header.dest_port, 53);
    ASSERT_EQ(packets[0].udp_header.length, 12);
}

TEST(test_packet_analyzer_ipv6_flow_label) {
    std::vector<uint8_t> packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x86, 0xDD,
        0x61, 0x23, 0x45, 0x67,
        0x00, 0x20, 0x06, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };

    PacketAnalyzer analyzer;
    analyzer.analyze(packet);

    const auto& packets = analyzer.getPackets();
    ASSERT_EQ(packets.size(), 1);
    ASSERT_TRUE(packets[0].has_ipv6);
    ASSERT_EQ(packets[0].ipv6_header.version, 6);
    ASSERT_EQ(packets[0].ipv6_header.traffic_class, 0x12);
    ASSERT_EQ(packets[0].ipv6_header.flow_label, 0x34567);
}

TEST(test_packet_analyzer_stats) {
    std::vector<uint8_t> packet1 = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x08, 0x00
    };
    
    std::vector<uint8_t> packet2 = packet1;
    
    PacketAnalyzer analyzer;
    analyzer.analyze(packet1);
    analyzer.analyze(packet2);
    
    const auto& stats = analyzer.getStats();
    ASSERT_EQ(stats.total_packets, 2);
    ASSERT_EQ(stats.total_bytes, packet1.size() * 2);
}

TEST(test_packet_filter_by_type) {
    std::vector<uint8_t> packet = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x08, 0x00
    };
    
    PacketAnalyzer analyzer;
    analyzer.analyze(packet);
    
    auto filtered = PacketFilter::apply(
        analyzer.getPackets(),
        PacketFilter::byType(PacketType::IPv4)
    );
    
    ASSERT_EQ(filtered.size(), 1);
}

TEST(test_packet_filter_by_port) {
    std::vector<uint8_t> packet = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x7a, 0xb5,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
        0x00, 0x50, 0x1f, 0x90,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x12, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    PacketAnalyzer analyzer;
    analyzer.analyze(packet);
    
    auto filtered = PacketFilter::apply(
        analyzer.getPackets(),
        PacketFilter::byPort(80)
    );
    
    ASSERT_EQ(filtered.size(), 1);
}

TEST(test_hexdump_classic) {
    std::vector<uint8_t> data = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x48, 0x65, 0x6c, 0x6c, 0x6f
    };
    
    HexDumpOptions options;
    options.format = HexDumpFormat::Classic;
    options.show_ascii = true;
    options.show_offset = true;
    
    HexDumper dumper(options);
    std::string output = dumper.dump(data);
    
    ASSERT_TRUE(output.find("00000000") != std::string::npos);
    ASSERT_TRUE(output.find("Hello") != std::string::npos);
}

TEST(test_hexdump_carray) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    
    HexDumpOptions options;
    options.format = HexDumpFormat::CArray;
    
    HexDumper dumper(options);
    std::string output = dumper.dump(data);
    
    ASSERT_TRUE(output.find("const uint8_t") != std::string::npos);
    ASSERT_TRUE(output.find("0x01") != std::string::npos);
    ASSERT_TRUE(output.find("0x02") != std::string::npos);
    ASSERT_TRUE(output.find("0x03") != std::string::npos);
}

TEST(test_hexdump_to_ascii) {
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', 0x00, 0x01, 0x7F};
    
    std::string ascii = HexDumper::toAscii(data);
    ASSERT_EQ(ascii, "Hello...");
}

TEST(test_binary_diff) {
    std::vector<uint8_t> a = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> b = {0x01, 0x02, 0xFF, 0x04, 0x05};
    
    auto diffs = BinaryDiff::compare(a, b);
    ASSERT_EQ(diffs.size(), 1);
    ASSERT_EQ(diffs[0].offset, 2);
    ASSERT_EQ(diffs[0].original, 0x03);
    ASSERT_EQ(diffs[0].modified, 0xFF);
    
    std::vector<uint8_t> same1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> same2 = {0x01, 0x02, 0x03};
    diffs = BinaryDiff::compare(same1, same2);
    ASSERT_EQ(diffs.size(), 0);
}

TEST(test_pattern_finder) {
    std::vector<uint8_t> data = {
        0x00, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF,
        0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x05
    };
    
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xBE, 0xEF};
    auto matches = PatternFinder::find(data, pattern);
    
    ASSERT_EQ(matches.size(), 2);
    ASSERT_EQ(matches[0].offset, 3);
    ASSERT_EQ(matches[1].offset, 9);
}

TEST(test_pattern_finder_hex) {
    std::vector<uint8_t> data = {
        0x00, 0x01, 0x02, 0xCA, 0xFE, 0xBA, 0xBE,
        0x03, 0x04, 0x05
    };
    
    auto matches = PatternFinder::findHex(data, "cafebabe");
    ASSERT_EQ(matches.size(), 1);
    ASSERT_EQ(matches[0].offset, 3);
}

TEST(test_pattern_finder_null_regions) {
    std::vector<uint8_t> data = {
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x04, 0x00, 0x00, 0x05
    };
    
    auto matches = PatternFinder::findNullRegions(data, 4);
    ASSERT_EQ(matches.size(), 1);
    ASSERT_EQ(matches[0].offset, 2);
    ASSERT_EQ(matches[0].pattern.size(), 5);
}

TEST(test_endianness_switch) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    
    ProtocolParser parser(Endianness::Little);
    uint32_t value;
    parser.parseUint32(data, 0, value);
    ASSERT_EQ(value, 0x04030201);
    
    parser.setEndianness(Endianness::Big);
    parser.parseUint32(data, 0, value);
    ASSERT_EQ(value, 0x01020304);
    
    ASSERT_EQ(parser.getEndianness(), Endianness::Big);
}

TEST(test_bytes_parsed_tracking) {
    ProtocolParser parser;
    std::vector<uint8_t> data = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    
    parser.parseUint8(data, 0, u8);
    ASSERT_EQ(parser.getBytesParsed(), 1);
    
    parser.parseUint16(data, 1, u16);
    ASSERT_EQ(parser.getBytesParsed(), 3);
    
    parser.parseUint32(data, 3, u32);
    ASSERT_EQ(parser.getBytesParsed(), 7);
    
    parser.parseUint64(data, 7, u64);
    ASSERT_EQ(parser.getBytesParsed(), 15);
    
    parser.resetBytesParsed();
    ASSERT_EQ(parser.getBytesParsed(), 0);
}

int main() {
    std::cout << "=== Binary Protocol Analyzer Unit Tests ===\n\n";
    
    RUN_TEST(test_parse_uint8);
    RUN_TEST(test_parse_uint16_little_endian);
    RUN_TEST(test_parse_uint16_big_endian);
    RUN_TEST(test_parse_uint32_little_endian);
    RUN_TEST(test_parse_uint32_big_endian);
    RUN_TEST(test_parse_uint64);
    RUN_TEST(test_parse_integers_signed);
    RUN_TEST(test_parse_float);
    RUN_TEST(test_parse_double);
    RUN_TEST(test_parse_string);
    RUN_TEST(test_parse_string_null_terminated);
    RUN_TEST(test_hex_string_to_bytes);
    RUN_TEST(test_bytes_to_hex_string);
    RUN_TEST(test_crc32);
    RUN_TEST(test_crc16);
    RUN_TEST(test_protocol_definition);
    RUN_TEST(test_packet_analyzer_ethernet);
    RUN_TEST(test_packet_analyzer_ipv4_tcp);
    RUN_TEST(test_packet_analyzer_ipv6);
    RUN_TEST(test_packet_analyzer_ipv6_tcp);
    RUN_TEST(test_packet_analyzer_ipv6_udp);
    RUN_TEST(test_packet_analyzer_ipv6_flow_label);
    RUN_TEST(test_packet_analyzer_stats);
    RUN_TEST(test_packet_filter_by_type);
    RUN_TEST(test_packet_filter_by_port);
    RUN_TEST(test_hexdump_classic);
    RUN_TEST(test_hexdump_carray);
    RUN_TEST(test_hexdump_to_ascii);
    RUN_TEST(test_binary_diff);
    RUN_TEST(test_pattern_finder);
    RUN_TEST(test_pattern_finder_hex);
    RUN_TEST(test_pattern_finder_null_regions);
    RUN_TEST(test_endianness_switch);
    RUN_TEST(test_bytes_parsed_tracking);
    
    std::cout << "\n=== Test Results ===\n";
    std::cout << "Passed: " << tests_passed << "/" << tests_run << "\n";
    
    if (tests_passed == tests_run) {
        std::cout << "All tests passed!\n";
        return 0;
    } else {
        std::cout << "Some tests failed.\n";
        return 1;
    }
}
