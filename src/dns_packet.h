#include <array>

class DNSMessage {
  public:
    static int convert_unsigned_char_tuple_into_int(unsigned char char_one, unsigned char char_two);
    static std::array<unsigned char, 12> create_header(char buffer[512]);
    static std::array<unsigned char, 12> create_question_section(std::array<unsigned char, 12> header, char buffer[512]);
    static std::array<unsigned char, 12> create_message_from_buffer(char buffer[512]);
};