#include <array>

class DNSMessage {
  public:
    static std::array<unsigned char, 12> create_message_from_buffer(char buffer[512]);
};