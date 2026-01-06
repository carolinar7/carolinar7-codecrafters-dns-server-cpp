#include "answer.h"
#include "question.h"
#include <netinet/in.h>
#include <array>
#include <vector>
#include <string>

class DNSPacket {
  private:
    // Initial input
    char buffer[512];
    int buffer_pointer;
    
    void create_initial_dns_packet();

    // Stored header
    std::array<unsigned char, 12> header;
    void create_header();

    // Stored question section
    int question_count;
    std::vector<Question> question_vector;
    void copy_question();
    void copy_pointer(std::vector<unsigned char> domain_vector, int pointer_loc);
    void create_question_section();

    // Stored answer section
    std::vector<Answer> answer_vector;
    void create_answer_section();
  public:
    static int convert_unsigned_char_tuple_into_int(unsigned char char_one, unsigned char char_two);
    static std::vector<unsigned char> convert_string_to_label_sequence(std::string str);
    DNSPacket(char buffer[512], sockaddr_in forwarding_address);
    DNSPacket(char buffer[512]);
    std::vector<unsigned char> get_return_packet();
};