#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <variant>

namespace bpa {

enum class Endianness {
    Little,
    Big
};

enum class ParseError {
    None,
    BufferTooSmall,
    InvalidFormat,
    OutOfBounds,
    ChecksumMismatch
};

struct ParseResult {
    ParseError error;
    std::string message;
    
    bool success() const { return error == ParseError::None; }
};

class ProtocolParser {
public:
    explicit ProtocolParser(Endianness endian = Endianness::Little);
    
    void setEndianness(Endianness endian);
    Endianness getEndianness() const;
    
    ParseResult parseUint8(const std::vector<uint8_t>& buffer, size_t offset, uint8_t& value);
    ParseResult parseUint16(const std::vector<uint8_t>& buffer, size_t offset, uint16_t& value);
    ParseResult parseUint32(const std::vector<uint8_t>& buffer, size_t offset, uint32_t& value);
    ParseResult parseUint64(const std::vector<uint8_t>& buffer, size_t offset, uint64_t& value);
    
    ParseResult parseInt8(const std::vector<uint8_t>& buffer, size_t offset, int8_t& value);
    ParseResult parseInt16(const std::vector<uint8_t>& buffer, size_t offset, int16_t& value);
    ParseResult parseInt32(const std::vector<uint8_t>& buffer, size_t offset, int32_t& value);
    ParseResult parseInt64(const std::vector<uint8_t>& buffer, size_t offset, int64_t& value);
    
    ParseResult parseFloat(const std::vector<uint8_t>& buffer, size_t offset, float& value);
    ParseResult parseDouble(const std::vector<uint8_t>& buffer, size_t offset, double& value);
    
    ParseResult parseString(const std::vector<uint8_t>& buffer, size_t offset, 
                           size_t length, std::string& value);
    ParseResult parseStringNullTerminated(const std::vector<uint8_t>& buffer, 
                                          size_t offset, std::string& value);
    
    ParseResult parseBytes(const std::vector<uint8_t>& buffer, size_t offset,
                          size_t length, std::vector<uint8_t>& value);
    
    static std::vector<uint8_t> hexStringToBytes(const std::string& hex);
    static std::string bytesToHexString(const std::vector<uint8_t>& bytes, 
                                        bool spaces = true);
    
    static uint32_t calculateCRC32(const std::vector<uint8_t>& data);
    static uint16_t calculateCRC16(const std::vector<uint8_t>& data);
    
    size_t getBytesParsed() const { return bytes_parsed_; }
    void resetBytesParsed() { bytes_parsed_ = 0; }
    
private:
    Endianness endianness_;
    size_t bytes_parsed_;
    
    bool checkBounds(const std::vector<uint8_t>& buffer, size_t offset, size_t size) const;
    uint16_t swapBytes(uint16_t value) const;
    uint32_t swapBytes(uint32_t value) const;
    uint64_t swapBytes(uint64_t value) const;
};

struct ProtocolField {
    std::string name;
    size_t offset;
    size_t size;
    std::variant<uint64_t, double, std::string> value;
    
    std::string valueToString() const;
};

struct ProtocolMessage {
    std::string name;
    std::vector<ProtocolField> fields;
    std::vector<uint8_t> raw_data;
    uint32_t crc32;
    
    std::string summary() const;
};

class ProtocolDefinition {
public:
    void setName(const std::string& name) { name_ = name; }
    std::string getName() const { return name_; }
    
    void addField(const std::string& field_name, size_t offset, size_t size);
    
    ProtocolMessage parse(const std::vector<uint8_t>& data, 
                         ProtocolParser& parser) const;
    
    size_t getMessageSize() const { return message_size_; }
    void setMessageSize(size_t size) { message_size_ = size; }
    
private:
    std::string name_;
    std::vector<ProtocolField> fields_;
    size_t message_size_ = 0;
};

} // namespace bpa

#endif // PROTOCOL_PARSER_H
