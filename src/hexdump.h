#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

namespace bpa {

enum class HexDumpFormat {
    Classic,
    Compact,
    Detailed,
    CArray
};

struct HexDumpOptions {
    HexDumpFormat format = HexDumpFormat::Classic;
    size_t bytes_per_line = 16;
    size_t group_size = 4;
    bool show_ascii = true;
    bool show_offset = true;
    bool show_uppercase = false;
    size_t base_offset = 0;
    bool color_output = false;
};

class HexDumper {
public:
    explicit HexDumper(const HexDumpOptions& options = HexDumpOptions());
    
    void setOptions(const HexDumpOptions& options);
    HexDumpOptions getOptions() const;
    
    std::string dump(const std::vector<uint8_t>& data) const;
    std::string dump(const uint8_t* data, size_t size) const;
    
    void print(const std::vector<uint8_t>& data, std::ostream& out = std::cout) const;
    void print(const uint8_t* data, size_t size, std::ostream& out = std::cout) const;
    
    static std::string toAscii(const std::vector<uint8_t>& data);
    static std::string toAscii(const uint8_t* data, size_t size);
    
private:
    HexDumpOptions options_;
    
    std::string dumpClassic(const uint8_t* data, size_t size) const;
    std::string dumpCompact(const uint8_t* data, size_t size) const;
    std::string dumpDetailed(const uint8_t* data, size_t size) const;
    std::string dumpCArray(const uint8_t* data, size_t size) const;
    
    std::string formatByte(uint8_t byte) const;
    std::string formatOffset(size_t offset) const;
    std::string formatAsciiGroup(const uint8_t* data, size_t size) const;
    
    const char* getResetColor() const;
    const char* getOffsetColor() const;
    const char* getHexColor() const;
    const char* getAsciiColor() const;
};

class BinaryDiff {
public:
    struct Difference {
        size_t offset;
        uint8_t original;
        uint8_t modified;
    };
    
    static std::vector<Difference> compare(const std::vector<uint8_t>& a,
                                           const std::vector<uint8_t>& b);
    
    static std::string diffReport(const std::vector<uint8_t>& a,
                                  const std::vector<uint8_t>& b,
                                  const HexDumpOptions& options = HexDumpOptions());
};

class PatternFinder {
public:
    struct Match {
        size_t offset;
        std::vector<uint8_t> pattern;
    };
    
    static std::vector<Match> find(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& pattern);
    
    static std::vector<Match> findHex(const std::vector<uint8_t>& data,
                                      const std::string& hex_pattern);
    
    static std::vector<Match> findRepeating(const std::vector<uint8_t>& data,
                                            uint8_t byte, size_t min_length = 4);
    
    static std::vector<Match> findNullRegions(const std::vector<uint8_t>& data,
                                              size_t min_length = 16);
};

} // namespace bpa

#endif // HEXDUMP_H
