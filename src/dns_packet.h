#include "answer.h"
#include "question.h"
#include <netinet/in.h>
#include <array>
#include <vector>
#include <string>

class DNSPacket {
  private:
    // Buffer Input
    char buffer[512];
    int buffer_pointer;
    void copy_buffer(char buffer[512]);
    
    // DNS Packet construction
    void copy_dns_packet(char buffer[512]);
    std::vector<unsigned char> create_question_packet(Question question);

    // Stored header
    std::array<unsigned char, 12> header;
    void copy_header();
    void create_header();

    // Stored question section
    int question_count;
    std::vector<Question> question_vector;
    void copy_question_section();
    void copy_question();

    // Stored answer section
    int answer_count;
    std::vector<Answer> answer_vector;
    void copy_answer_section();
    void create_answer_section();

    // Shared utilities
    std::vector<unsigned char> copy_domain_name();
    void copy_pointer(std::vector<unsigned char> &domain_vector, int pointer_loc);

    // Forwarder Helpers
    void create_answer_section_with_forwarding_address(sockaddr_in forwarding_address);
  public:
    // Constructors
    DNSPacket();
    DNSPacket(char buffer[512]);

    // Getters
    std::vector<unsigned char> get_packet_vector();
    std::vector<Answer> get_answer_section();

    //  Helpers
    static int convert_unsigned_char_tuple_into_int(unsigned char char_one, unsigned char char_two);

    // Responses
    static DNSPacket respond_to_packet(DNSPacket packet);
    static DNSPacket forward_packet(DNSPacket packet, sockaddr_in forwarding_address);
    void mutate_for_response(DNSPacket packet);
    void mutate_for_forward_response(DNSPacket packet, sockaddr_in forwarding_address);

    // Print functions
    void print_dns_packet();
    void print_header();
    void print_all_questions();
    void print_all_answers();
};