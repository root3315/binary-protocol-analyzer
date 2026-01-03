#include "hexdump.h"
#include "protocol_parser.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace bpa {

HexDumper::HexDumper(const HexDumpOptions& options) : options_(options) {}

void HexDumper::setOptions(const HexDumpOptions& options) {
    options_ = options;
}

HexDumpOptions HexDumper::getOptions() const {
    return options_;
}

std::string HexDumper::dump(const std::vector<uint8_t>& data) const {
    return dump(data.data(), data.size());
}

std::string HexDumper::dump(const uint8_t* data, size_t size) const {
    switch (options_.format) {
        case HexDumpFormat::Classic:
            return dumpClassic(data, size);
        case HexDumpFormat::Compact:
            return dumpCompact(data, size);
        case HexDumpFormat::Detailed:
            return dumpDetailed(data, size);
        case HexDumpFormat::CArray:
            return dumpCArray(data, size);
        default:
            return dumpClassic(data, size);
    }
}

void HexDumper::print(const std::vector<uint8_t>& data, std::ostream& out) const {
    print(data.data(), data.size(), out);
}

void HexDumper::print(const uint8_t* data, size_t size, std::ostream& out) const {
    out << dump(data, size);
}

std::string HexDumper::toAscii(const std::vector<uint8_t>& data) {
    return toAscii(data.data(), data.size());
}

std::string HexDumper::toAscii(const uint8_t* data, size_t size) {
    std::string result;
    result.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        char c = static_cast<char>(data[i]);
        if (std::isprint(static_cast<unsigned char>(c))) {
            result.push_back(c);
        } else {
            result.push_back('.');
        }
    }
    return result;
}

std::string HexDumper::dumpClassic(const uint8_t* data, size_t size) const {
    std::ostringstream oss;
    size_t bytes_per_line = options_.bytes_per_line;
    
    for (size_t i = 0; i < size; i += bytes_per_line) {
        if (options_.color_output) {
            oss << getOffsetColor();
        }
        
        if (options_.show_offset) {
            oss << formatOffset(options_.base_offset + i);
        }
        
        if (options_.color_output) {
            oss << getResetColor() << "  ";
            oss << getHexColor();
        } else {
            oss << "  ";
        }
        
        std::string ascii_line;
        size_t line_end = std::min(i + bytes_per_line, size);
        
        for (size_t j = i; j < line_end; ++j) {
            if (j > i && j % options_.group_size == 0) {
                oss << " ";
            }
            oss << formatByte(data[j]);
            
            char c = static_cast<char>(data[j]);
            ascii_line.push_back(std::isprint(static_cast<unsigned char>(c)) ? c : '.');
        }
        
        size_t remaining = bytes_per_line - (line_end - i);
        for (size_t j = 0; j < remaining; ++j) {
            if ((bytes_per_line - remaining) > 0 && 
                (bytes_per_line - remaining + j * options_.group_size) % options_.group_size == 0) {
                oss << "  ";
            } else if (j > 0 && (bytes_per_line - remaining + j) % options_.group_size == 0) {
                oss << "  ";
            } else {
                oss << "   ";
            }
        }
        
        if (options_.color_output) {
            oss << getResetColor();
        }
        
        if (options_.show_ascii) {
            if (options_.color_output) {
                oss << "  " << getAsciiColor() << "|" << ascii_line << "|" 
                    << getResetColor();
            } else {
                oss << "  |" << ascii_line << "|";
            }
        }
        
        oss << "\n";
    }
    
    return oss.str();
}

std::string HexDumper::dumpCompact(const uint8_t* data, size_t size) const {
    std::ostringstream oss;
    
    for (size_t i = 0; i < size; ++i) {
        if (i > 0 && i % options_.bytes_per_line == 0) {
            oss << "\n";
        } else if (i > 0) {
            oss << " ";
        }
        oss << formatByte(data[i]);
    }
    
    return oss.str();
}

std::string HexDumper::dumpDetailed(const uint8_t* data, size_t size) const {
    std::ostringstream oss;
    
    oss << "Hex Dump Details\n";
    oss << "================\n";
    oss << "Total bytes: " << size << "\n";
    oss << "Bytes per line: " << options_.bytes_per_line << "\n\n";
    
    for (size_t i = 0; i < size; i += options_.bytes_per_line) {
        if (options_.show_offset) {
            oss << formatOffset(options_.base_offset + i) << "  ";
        }
        
        size_t line_end = std::min(i + options_.bytes_per_line, size);
        
        for (size_t j = i; j < line_end; ++j) {
            oss << formatByte(data[j]);
            
            oss << " [" << std::dec << static_cast<int>(data[j]) << "]";
            if (j < line_end - 1) oss << " ";
        }
        
        if (options_.show_ascii) {
            oss << "  |";
            for (size_t j = i; j < line_end; ++j) {
                char c = static_cast<char>(data[j]);
                oss << (std::isprint(static_cast<unsigned char>(c)) ? c : '.');
            }
            oss << "|";
        }
        
        oss << "\n";
    }
    
    return oss.str();
}

std::string HexDumper::dumpCArray(const uint8_t* data, size_t size) const {
    std::ostringstream oss;
    
    oss << "const uint8_t data[" << size << "] = {\n    ";
    
    for (size_t i = 0; i < size; ++i) {
        if (i > 0) {
            if (i % options_.bytes_per_line == 0) {
                oss << "\n    ";
            } else {
                oss << " ";
            }
        }
        
        oss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(data[i]) << ",";
    }
    
    oss << "\n};\n";
    
    return oss.str();
}

std::string HexDumper::formatByte(uint8_t byte) const {
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0');
    
    if (options_.show_uppercase) {
        oss << std::uppercase;
    }
    
    oss << static_cast<int>(byte);
    
    if (options_.show_uppercase) {
        oss << std::nouppercase;
    }
    
    return oss.str();
}

std::string HexDumper::formatOffset(size_t offset) const {
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << offset;
    return oss.str();
}

std::string HexDumper::formatAsciiGroup(const uint8_t* data, size_t size) const {
    std::string result;
    for (size_t i = 0; i < size; ++i) {
        char c = static_cast<char>(data[i]);
        result.push_back(std::isprint(static_cast<unsigned char>(c)) ? c : '.');
    }
    return result;
}

const char* HexDumper::getResetColor() const {
    return "\033[0m";
}

const char* HexDumper::getOffsetColor() const {
    return "\033[36m";
}

const char* HexDumper::getHexColor() const {
    return "\033[33m";
}

const char* HexDumper::getAsciiColor() const {
    return "\033[32m";
}

std::vector<BinaryDiff::Difference> BinaryDiff::compare(
        const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<Difference> diffs;
    
    size_t min_size = std::min(a.size(), b.size());
    size_t max_size = std::max(a.size(), b.size());
    
    for (size_t i = 0; i < min_size; ++i) {
        if (a[i] != b[i]) {
            diffs.push_back({i, a[i], b[i]});
        }
    }
    
    for (size_t i = min_size; i < max_size; ++i) {
        if (a.size() > b.size()) {
            diffs.push_back({i, a[i], 0});
        } else {
            diffs.push_back({i, 0, b[i]});
        }
    }
    
    return diffs;
}

std::string BinaryDiff::diffReport(const std::vector<uint8_t>& a,
                                    const std::vector<uint8_t>& b,
                                    const HexDumpOptions& options) {
    std::ostringstream oss;
    
    auto diffs = compare(a, b);
    
    oss << "Binary Diff Report\n";
    oss << "==================\n\n";
    oss << "File A size: " << a.size() << " bytes\n";
    oss << "File B size: " << b.size() << " bytes\n";
    oss << "Differences found: " << diffs.size() << "\n\n";
    
    if (diffs.empty()) {
        oss << "Files are identical.\n";
        return oss.str();
    }
    
    oss << "Differences:\n";
    for (const auto& diff : diffs) {
        oss << "  Offset 0x" << std::hex << diff.offset << std::dec << ": "
            << "0x" << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(diff.original) << std::dec << " -> "
            << "0x" << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(diff.modified) << std::dec << "\n";
    }
    
    return oss.str();
}

std::vector<PatternFinder::Match> PatternFinder::find(
        const std::vector<uint8_t>& data, const std::vector<uint8_t>& pattern) {
    std::vector<Match> matches;
    
    if (pattern.empty() || data.size() < pattern.size()) {
        return matches;
    }
    
    for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        
        if (found) {
            matches.push_back({i, pattern});
        }
    }
    
    return matches;
}

std::vector<PatternFinder::Match> PatternFinder::findHex(
        const std::vector<uint8_t>& data, const std::string& hex_pattern) {
    auto pattern = ProtocolParser::hexStringToBytes(hex_pattern);
    return find(data, pattern);
}

std::vector<PatternFinder::Match> PatternFinder::findRepeating(
        const std::vector<uint8_t>& data, uint8_t byte, size_t min_length) {
    std::vector<Match> matches;
    
    size_t i = 0;
    while (i < data.size()) {
        if (data[i] == byte) {
            size_t start = i;
            while (i < data.size() && data[i] == byte) {
                ++i;
            }
            
            size_t length = i - start;
            if (length >= min_length) {
                Match match;
                match.offset = start;
                match.pattern.assign(length, byte);
                matches.push_back(match);
            }
        } else {
            ++i;
        }
    }
    
    return matches;
}

std::vector<PatternFinder::Match> PatternFinder::findNullRegions(
        const std::vector<uint8_t>& data, size_t min_length) {
    return findRepeating(data, 0x00, min_length);
}

} // namespace bpa
