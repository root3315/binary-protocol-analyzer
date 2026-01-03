#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include "protocol_parser.h"
#include <map>
#include <functional>

namespace bpa {

enum class PacketType {
    Unknown,
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    HTTP,
    TLS,
    Custom
};

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
    
    std::string destMacString() const;
    std::string srcMacString() const;
};

struct IPv4Header {
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_addr;
    uint32_t dest_addr;

    std::string srcAddrString() const;
    std::string destAddrString() const;
    size_t headerSize() const { return ihl * 4; }
};

struct IPv6Header {
    uint8_t version;
    uint8_t traffic_class;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dest_addr[16];

    std::string srcAddrString() const;
    std::string destAddrString() const;
    size_t headerSize() const { return 40; }
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    
    size_t headerSize() const { return (data_offset >> 4) * 4; }
    bool flagSyn() const { return (flags & 0x02) != 0; }
    bool flagAck() const { return (flags & 0x10) != 0; }
    bool flagFin() const { return (flags & 0x01) != 0; }
    bool flagRst() const { return (flags & 0x04) != 0; }
    bool flagPsh() const { return (flags & 0x08) != 0; }
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct PacketInfo {
    PacketType type;
    size_t total_size;
    size_t header_size;
    size_t payload_size;
    std::string description;
    std::vector<uint8_t> raw_data;

    EthernetHeader eth_header;
    IPv4Header ipv4_header;
    IPv6Header ipv6_header;
    TCPHeader tcp_header;
    UDPHeader udp_header;

    bool has_eth = false;
    bool has_ipv4 = false;
    bool has_ipv6 = false;
    bool has_tcp = false;
    bool has_udp = false;
};

struct AnalysisStats {
    size_t total_packets;
    size_t total_bytes;
    std::map<PacketType, size_t> packet_counts;
    std::map<uint16_t, size_t> port_counts;
    std::map<std::string, size_t> mac_counts;
    size_t tcp_syn_count;
    size_t tcp_fin_count;
    size_t tcp_rst_count;
    size_t malformed_count;
    
    AnalysisStats() : total_packets(0), total_bytes(0),
                      tcp_syn_count(0), tcp_fin_count(0),
                      tcp_rst_count(0), malformed_count(0) {}
};

class PacketAnalyzer {
public:
    PacketAnalyzer();
    
    void analyze(const std::vector<uint8_t>& packet);
    void analyzeMultiple(const std::vector<std::vector<uint8_t>>& packets);
    
    const std::vector<PacketInfo>& getPackets() const { return packets_; }
    const AnalysisStats& getStats() const { return stats_; }
    
    void reset();
    
    std::string generateReport() const;
    std::string getTopTalkers(size_t count = 5) const;
    std::string getPortDistribution() const;
    
    static PacketType detectPacketType(const std::vector<uint8_t>& packet);
    
private:
    std::vector<PacketInfo> packets_;
    AnalysisStats stats_;
    ProtocolParser parser_;
    
    void parseEthernet(const std::vector<uint8_t>& data, PacketInfo& info);
    void parseIPv4(const std::vector<uint8_t>& data, size_t offset, PacketInfo& info);
    void parseIPv6(const std::vector<uint8_t>& data, size_t offset, PacketInfo& info);
    void parseTCP(const std::vector<uint8_t>& data, size_t offset, PacketInfo& info);
    void parseUDP(const std::vector<uint8_t>& data, size_t offset, PacketInfo& info);

    void updateStats(const PacketInfo& info);
    std::string macToString(const uint8_t mac[6]) const;
    std::string ipv4ToString(uint32_t addr) const;
    std::string ipv6ToString(const uint8_t addr[16]) const;
};

class PacketFilter {
public:
    using FilterFunc = std::function<bool(const PacketInfo&)>;
    
    static FilterFunc byType(PacketType type);
    static FilterFunc byPort(uint16_t port);
    static FilterFunc byMac(const std::string& mac);
    static FilterFunc byIp(const std::string& ip);
    static FilterFunc byMinSize(size_t min_size);
    static FilterFunc byMaxSize(size_t max_size);
    static FilterFunc tcpSyn();
    static FilterFunc tcpRst();
    
    static std::vector<PacketInfo> apply(const std::vector<PacketInfo>& packets,
                                         const FilterFunc& filter);
};

} // namespace bpa

#endif // PACKET_ANALYZER_H
