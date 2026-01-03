#include "packet_analyzer.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace bpa {

std::string EthernetHeader::destMacString() const {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(dest_mac[i]);
    }
    return oss.str();
}

std::string EthernetHeader::srcMacString() const {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(src_mac[i]);
    }
    return oss.str();
}

std::string IPv4Header::srcAddrString() const {
    std::ostringstream oss;
    oss << ((src_addr >> 24) & 0xFF) << "."
        << ((src_addr >> 16) & 0xFF) << "."
        << ((src_addr >> 8) & 0xFF) << "."
        << (src_addr & 0xFF);
    return oss.str();
}

std::string IPv4Header::destAddrString() const {
    std::ostringstream oss;
    oss << ((dest_addr >> 24) & 0xFF) << "."
        << ((dest_addr >> 16) & 0xFF) << "."
        << ((dest_addr >> 8) & 0xFF) << "."
        << (dest_addr & 0xFF);
    return oss.str();
}

std::string IPv6Header::srcAddrString() const {
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t segment = (static_cast<uint16_t>(src_addr[i]) << 8) |
                           static_cast<uint16_t>(src_addr[i + 1]);
        oss << std::hex << segment << std::dec;
    }
    return oss.str();
}

std::string IPv6Header::destAddrString() const {
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t segment = (static_cast<uint16_t>(dest_addr[i]) << 8) |
                           static_cast<uint16_t>(dest_addr[i + 1]);
        oss << std::hex << segment << std::dec;
    }
    return oss.str();
}

PacketAnalyzer::PacketAnalyzer() : parser_(Endianness::Big) {}

void PacketAnalyzer::reset() {
    packets_.clear();
    stats_ = AnalysisStats();
}

PacketType PacketAnalyzer::detectPacketType(const std::vector<uint8_t>& packet) {
    if (packet.size() < 14) {
        return PacketType::Unknown;
    }
    
    uint16_t ether_type = (static_cast<uint16_t>(packet[12]) << 8) | 
                          static_cast<uint16_t>(packet[13]);
    
    if (ether_type == 0x0800) {
        return PacketType::IPv4;
    } else if (ether_type == 0x86DD) {
        return PacketType::IPv6;
    } else if (ether_type == 0x0806) {
        return PacketType::Ethernet;
    }
    
    return PacketType::Unknown;
}

void PacketAnalyzer::analyze(const std::vector<uint8_t>& packet) {
    if (packet.size() < 14) {
        stats_.malformed_count++;
        return;
    }

    PacketInfo info;
    info.raw_data = packet;
    info.total_size = packet.size();
    info.type = detectPacketType(packet);

    parseEthernet(packet, info);

    if (info.type == PacketType::IPv4) {
        parseIPv4(packet, 14, info);
    } else if (info.type == PacketType::IPv6) {
        parseIPv6(packet, 14, info);
    }

    if (info.has_ipv4) {
        size_t ip_header_end = 14 + info.ipv4_header.headerSize();
        uint8_t protocol = info.ipv4_header.protocol;

        if (protocol == 6 && ip_header_end < packet.size()) {
            parseTCP(packet, ip_header_end, info);
        } else if (protocol == 17 && ip_header_end < packet.size()) {
            parseUDP(packet, ip_header_end, info);
        }
    }

    info.payload_size = info.total_size - info.header_size;
    updateStats(info);
    packets_.push_back(info);
}

void PacketAnalyzer::analyzeMultiple(const std::vector<std::vector<uint8_t>>& packets) {
    for (const auto& packet : packets) {
        analyze(packet);
    }
}

void PacketAnalyzer::parseEthernet(const std::vector<uint8_t>& data, PacketInfo& info) {
    if (data.size() < 14) return;
    
    for (int i = 0; i < 6; ++i) {
        info.eth_header.dest_mac[i] = data[i];
        info.eth_header.src_mac[i] = data[6 + i];
    }
    
    info.eth_header.ether_type = (static_cast<uint16_t>(data[12]) << 8) | 
                                  static_cast<uint16_t>(data[13]);
    info.has_eth = true;
    info.header_size = 14;
    
    std::ostringstream desc;
    desc << "Ethernet: " << info.eth_header.srcMacString() 
         << " -> " << info.eth_header.destMacString();
    info.description = desc.str();
}

void PacketAnalyzer::parseIPv4(const std::vector<uint8_t>& data, size_t offset,
                                PacketInfo& info) {
    if (offset + 20 > data.size()) return;
    
    IPv4Header& ip = info.ipv4_header;
    
    uint8_t ver_ihl = data[offset];
    ip.version = (ver_ihl >> 4) & 0x0F;
    ip.ihl = ver_ihl & 0x0F;
    
    if (ip.version != 4 || ip.ihl < 5) return;
    
    ip.dscp = (data[offset + 1] >> 2) & 0x3F;
    ip.ecn = data[offset + 1] & 0x03;
    
    parser_.parseUint16(data, offset + 2, ip.total_length);
    parser_.parseUint16(data, offset + 4, ip.identification);
    
    uint16_t flags_frag;
    parser_.parseUint16(data, offset + 6, flags_frag);
    ip.flags = (flags_frag >> 13) & 0x07;
    ip.fragment_offset = flags_frag & 0x1FFF;
    
    ip.ttl = data[offset + 8];
    ip.protocol = data[offset + 9];
    
    parser_.parseUint16(data, offset + 10, ip.header_checksum);
    parser_.parseUint32(data, offset + 12, ip.src_addr);
    parser_.parseUint32(data, offset + 16, ip.dest_addr);
    
    info.has_ipv4 = true;
    info.header_size = offset + ip.headerSize();
    
    std::ostringstream desc;
    desc << info.description << " | IPv4: " << ip.srcAddrString()
         << " -> " << ip.destAddrString();
    info.description = desc.str();
}

void PacketAnalyzer::parseIPv6(const std::vector<uint8_t>& data, size_t offset,
                                PacketInfo& info) {
    if (offset + 40 > data.size()) return;

    IPv6Header& ip6 = info.ipv6_header;

    uint8_t ver_tc = data[offset];
    ip6.version = (ver_tc >> 4) & 0x0F;
    ip6.traffic_class = (ver_tc & 0x0F) << 4;

    uint8_t tc_fl = data[offset + 1];
    ip6.traffic_class |= (tc_fl >> 4) & 0x0F;
    ip6.flow_label = (tc_fl & 0x0F) << 16;

    uint16_t flow_label_low;
    parser_.parseUint16(data, offset + 2, flow_label_low);
    ip6.flow_label |= flow_label_low;

    parser_.parseUint16(data, offset + 4, ip6.payload_length);
    ip6.next_header = data[offset + 6];
    ip6.hop_limit = data[offset + 7];

    for (int i = 0; i < 16; ++i) {
        ip6.src_addr[i] = data[offset + 8 + i];
        ip6.dest_addr[i] = data[offset + 24 + i];
    }

    if (ip6.version != 6) return;

    info.has_ipv6 = true;
    info.header_size = offset + ip6.headerSize();

    std::ostringstream desc;
    desc << info.description << " | IPv6: " << ip6.srcAddrString()
         << " -> " << ip6.destAddrString();
    info.description = desc.str();

    uint8_t next_header = ip6.next_header;
    size_t next_offset = offset + 40;

    if (next_header == 6 && next_offset < data.size()) {
        parseTCP(data, next_offset, info);
    } else if (next_header == 17 && next_offset < data.size()) {
        parseUDP(data, next_offset, info);
    } else if (next_header == 58 && next_offset < data.size()) {
        info.type = PacketType::ICMP;
    }
}

void PacketAnalyzer::parseTCP(const std::vector<uint8_t>& data, size_t offset,
                               PacketInfo& info) {
    if (offset + 20 > data.size()) return;
    
    TCPHeader& tcp = info.tcp_header;
    
    parser_.parseUint16(data, offset, tcp.src_port);
    parser_.parseUint16(data, offset + 2, tcp.dest_port);
    parser_.parseUint32(data, offset + 4, tcp.seq_num);
    parser_.parseUint32(data, offset + 8, tcp.ack_num);
    
    tcp.data_offset = data[offset + 12];
    tcp.flags = data[offset + 13];
    
    parser_.parseUint16(data, offset + 14, tcp.window);
    parser_.parseUint16(data, offset + 16, tcp.checksum);
    parser_.parseUint16(data, offset + 18, tcp.urgent_ptr);
    
    info.has_tcp = true;
    info.header_size = offset + tcp.headerSize();
    
    std::ostringstream desc;
    desc << info.description << " | TCP: " << tcp.src_port 
         << " -> " << tcp.dest_port;
    if (tcp.flagSyn()) desc << " [SYN]";
    if (tcp.flagAck()) desc << " [ACK]";
    if (tcp.flagFin()) desc << " [FIN]";
    if (tcp.flagRst()) desc << " [RST]";
    info.description = desc.str();
}

void PacketAnalyzer::parseUDP(const std::vector<uint8_t>& data, size_t offset,
                               PacketInfo& info) {
    if (offset + 8 > data.size()) return;
    
    UDPHeader& udp = info.udp_header;
    
    parser_.parseUint16(data, offset, udp.src_port);
    parser_.parseUint16(data, offset + 2, udp.dest_port);
    parser_.parseUint16(data, offset + 4, udp.length);
    parser_.parseUint16(data, offset + 6, udp.checksum);
    
    info.has_udp = true;
    info.header_size = offset + 8;
    
    std::ostringstream desc;
    desc << info.description << " | UDP: " << udp.src_port 
         << " -> " << udp.dest_port;
    info.description = desc.str();
}

void PacketAnalyzer::updateStats(const PacketInfo& info) {
    stats_.total_packets++;
    stats_.total_bytes += info.total_size;
    stats_.packet_counts[info.type]++;

    if (info.has_eth) {
        std::string src_mac = macToString(info.eth_header.src_mac);
        stats_.mac_counts[src_mac]++;
    }

    if (info.has_ipv6) {
        std::string src_ip = ipv6ToString(info.ipv6_header.src_addr);
        stats_.mac_counts[src_ip]++;
    }

    if (info.has_tcp) {
        stats_.port_counts[info.tcp_header.src_port]++;
        stats_.port_counts[info.tcp_header.dest_port]++;
        
        if (info.tcp_header.flagSyn()) stats_.tcp_syn_count++;
        if (info.tcp_header.flagFin()) stats_.tcp_fin_count++;
        if (info.tcp_header.flagRst()) stats_.tcp_rst_count++;
    }
    
    if (info.has_udp) {
        stats_.port_counts[info.udp_header.src_port]++;
        stats_.port_counts[info.udp_header.dest_port]++;
    }
}

std::string PacketAnalyzer::macToString(const uint8_t mac[6]) const {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string PacketAnalyzer::ipv4ToString(uint32_t addr) const {
    std::ostringstream oss;
    oss << ((addr >> 24) & 0xFF) << "."
        << ((addr >> 16) & 0xFF) << "."
        << ((addr >> 8) & 0xFF) << "."
        << (addr & 0xFF);
    return oss.str();
}

std::string PacketAnalyzer::ipv6ToString(const uint8_t addr[16]) const {
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t segment = (static_cast<uint16_t>(addr[i]) << 8) |
                           static_cast<uint16_t>(addr[i + 1]);
        oss << std::hex << segment << std::dec;
    }
    return oss.str();
}

std::string PacketAnalyzer::generateReport() const {
    std::ostringstream oss;
    
    oss << "=== Packet Analysis Report ===\n\n";
    oss << "Summary:\n";
    oss << "  Total Packets: " << stats_.total_packets << "\n";
    oss << "  Total Bytes:   " << stats_.total_bytes << "\n";
    oss << "  Malformed:     " << stats_.malformed_count << "\n\n";
    
    oss << "Packet Types:\n";
    for (const auto& [type, count] : stats_.packet_counts) {
        oss << "  ";
        switch (type) {
            case PacketType::Ethernet: oss << "Ethernet"; break;
            case PacketType::IPv4: oss << "IPv4"; break;
            case PacketType::IPv6: oss << "IPv6"; break;
            case PacketType::TCP: oss << "TCP"; break;
            case PacketType::UDP: oss << "UDP"; break;
            case PacketType::ICMP: oss << "ICMP"; break;
            case PacketType::HTTP: oss << "HTTP"; break;
            case PacketType::TLS: oss << "TLS"; break;
            default: oss << "Unknown"; break;
        }
        oss << ": " << count << "\n";
    }
    
    oss << "\nTCP Flags:\n";
    oss << "  SYN: " << stats_.tcp_syn_count << "\n";
    oss << "  FIN: " << stats_.tcp_fin_count << "\n";
    oss << "  RST: " << stats_.tcp_rst_count << "\n";
    
    return oss.str();
}

std::string PacketAnalyzer::getTopTalkers(size_t count) const {
    std::vector<std::pair<std::string, size_t>> sorted_macs(
        stats_.mac_counts.begin(), stats_.mac_counts.end());
    
    std::sort(sorted_macs.begin(), sorted_macs.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::ostringstream oss;
    oss << "Top " << std::min(count, sorted_macs.size()) << " MAC Addresses:\n";
    
    for (size_t i = 0; i < std::min(count, sorted_macs.size()); ++i) {
        oss << "  " << (i + 1) << ". " << sorted_macs[i].first 
            << " (" << sorted_macs[i].second << " packets)\n";
    }
    
    return oss.str();
}

std::string PacketAnalyzer::getPortDistribution() const {
    std::vector<std::pair<uint16_t, size_t>> sorted_ports(
        stats_.port_counts.begin(), stats_.port_counts.end());
    
    std::sort(sorted_ports.begin(), sorted_ports.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::ostringstream oss;
    oss << "Port Distribution (Top 10):\n";
    
    for (size_t i = 0; i < std::min(size_t(10), sorted_ports.size()); ++i) {
        oss << "  Port " << sorted_ports[i].first << ": " 
            << sorted_ports[i].second << " packets\n";
    }
    
    return oss.str();
}

PacketFilter::FilterFunc PacketFilter::byType(PacketType type) {
    return [type](const PacketInfo& info) { return info.type == type; };
}

PacketFilter::FilterFunc PacketFilter::byPort(uint16_t port) {
    return [port](const PacketInfo& info) {
        if (info.has_tcp) {
            return info.tcp_header.src_port == port || 
                   info.tcp_header.dest_port == port;
        }
        if (info.has_udp) {
            return info.udp_header.src_port == port || 
                   info.udp_header.dest_port == port;
        }
        return false;
    };
}

PacketFilter::FilterFunc PacketFilter::byMac(const std::string& mac) {
    return [mac](const PacketInfo& info) {
        if (!info.has_eth) return false;
        return info.eth_header.srcMacString() == mac || 
               info.eth_header.destMacString() == mac;
    };
}

PacketFilter::FilterFunc PacketFilter::byIp(const std::string& ip) {
    return [ip](const PacketInfo& info) {
        if (!info.has_ipv4) return false;
        return info.ipv4_header.srcAddrString() == ip || 
               info.ipv4_header.destAddrString() == ip;
    };
}

PacketFilter::FilterFunc PacketFilter::byMinSize(size_t min_size) {
    return [min_size](const PacketInfo& info) { 
        return info.total_size >= min_size; 
    };
}

PacketFilter::FilterFunc PacketFilter::byMaxSize(size_t max_size) {
    return [max_size](const PacketInfo& info) { 
        return info.total_size <= max_size; 
    };
}

PacketFilter::FilterFunc PacketFilter::tcpSyn() {
    return [](const PacketInfo& info) {
        return info.has_tcp && info.tcp_header.flagSyn();
    };
}

PacketFilter::FilterFunc PacketFilter::tcpRst() {
    return [](const PacketInfo& info) {
        return info.has_tcp && info.tcp_header.flagRst();
    };
}

std::vector<PacketInfo> PacketFilter::apply(const std::vector<PacketInfo>& packets,
                                             const FilterFunc& filter) {
    std::vector<PacketInfo> result;
    for (const auto& packet : packets) {
        if (filter(packet)) {
            result.push_back(packet);
        }
    }
    return result;
}

} // namespace bpa
