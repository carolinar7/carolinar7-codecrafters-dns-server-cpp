
#include "dns_packet.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include <array>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <cstring>

const std::string DOMAIN_NAME = "codecrafters.io";
const std::string NAME_DELIMETER = ".";
const int HEADER_BYTE_SIZE = 12;
const int BUFFER_SIZE = 512;

// ============================================================================
// DNS PACKET Construction
// ============================================================================

DNSPacket::DNSPacket(char buf[BUFFER_SIZE]) {
  this->buffer_pointer = 0;
  copy_dns_packet(buf);
}

DNSPacket::DNSPacket() {
  this->buffer_pointer = 0;
}

void DNSPacket::copy_dns_packet(char buf[BUFFER_SIZE]) {
  copy_buffer(buf);
  copy_header();
  copy_question_section();
  copy_answer_section();
}

std::vector<unsigned char> DNSPacket::create_question_packet(Question question) {
  std::vector<unsigned char> return_packet;

  // Copy transaction ID from buffer (original query)
  return_packet.push_back(buffer[0]);
  return_packet.push_back(buffer[1]);

  // Flags byte 2: QR=0 (query), copy OPCODE and RD from original
  unsigned char opcode = (0x0F << 3) & buffer[2];
  unsigned char recursion_desired = 0x01 & buffer[2];
  return_packet.push_back(opcode | recursion_desired);  // QR=0 for query

  // Flags byte 3: all zeros
  return_packet.push_back(0x00);

  // Question count: 1
  return_packet.push_back(0x00);
  return_packet.push_back(0x01);

  // Answer count: 0
  return_packet.push_back(0x00);
  return_packet.push_back(0x00);

  // Authority count: 0
  return_packet.push_back(0x00);
  return_packet.push_back(0x00);

  // Additional count: 0
  return_packet.push_back(0x00);
  return_packet.push_back(0x00);

  // Add the question
  question.add_question_into_return_packet(&return_packet);

  return return_packet;
}

// ============================================================================
// DNS PACKET Getters
// ============================================================================

std::vector<unsigned char> DNSPacket::get_packet_vector() {
  std::vector<unsigned char> return_packet;

  // Header section
  for (auto i = 0; i < this->header.size(); i++) {
    return_packet.push_back(this->header[i]);
  }

  // Question section
  for (auto i = 0; i < this->question_vector.size(); i++) {
    this->question_vector[i].add_question_into_return_packet(&return_packet);
  }

  // Answer section
  for (auto i = 0; i < this->answer_vector.size(); i++) {
    this->answer_vector[i].add_answer_into_return_packet(&return_packet);
  }

  return return_packet;
}

std::vector<Answer> DNSPacket::get_answer_section() {
  return this->answer_vector;
}

// ============================================================================
// DNS PACKET Buffer Helpers
// ============================================================================

void DNSPacket::copy_buffer(char buf[BUFFER_SIZE]) {
  for (int i = 0; i < BUFFER_SIZE; i++) {
    this->buffer[i] = buf[i];
  }
}

// ============================================================================
// DNS PACKET Header Helpers
// ============================================================================

void DNSPacket::copy_header() {
  for (auto i = 0; i < HEADER_BYTE_SIZE; i++) {
    this->header[i] = this->buffer[i];
  }
  // We've created the header so now our index is at 12. Header range: [0, 11].
  this->buffer_pointer = HEADER_BYTE_SIZE;
}

void DNSPacket::create_header() {
  // Create 12 byte response
  // Packet Identifier (ID) - same as ID of query packet - 16 bit.
  this->header[0] = buffer[0];
  this->header[1] = buffer[1];
  // The rest should fit in 8 bits.
  // Query/Response Indicator (QR) - One is for a reply packet - 1 bit.
  unsigned char qr_indicator = 1 << 7;
  // OP Code - Zero is a standard lookup / query - 4 bits. Computing from buffer query.
  unsigned char opcode = (0x0F << 3) & buffer[2];
  // Authoritive Answer - Zero since we don't own the the domain - 1 bit.
  unsigned char auth_answer = 0x00;
  // Truncation - UDP response so always 0 - 1 bit.
  unsigned char truncation = 0x00;
  // Recursion Desired - From the buffer query - 1 bit.
  unsigned char recursion_desired = 0x01 & buffer[2];
  this->header[2] = qr_indicator | opcode | auth_answer | truncation | recursion_desired;
  // Recursion Available - Zero since it's not available - 1 bit.
  // Reserved - Not used, so zero - 3 bits.
  // Response Code - status of the response zero (no error) - 4 bits.
  unsigned char response_code = opcode == 0x00 ? 0x00 : 0x04;
  this->header[3] = response_code;
  // Question count - number of questions in the question section. (We don't
  // know so 0 for now) - 16 bits.
  this->header[4] = buffer[4];
  this->header[5] = buffer[5];
  // Answer Record count - number of records in the answer section (Setting to same values as question count) - 16 bits.
  this->header[6] = buffer[4];
  this->header[7] = buffer[5];
  // Authority Record count - number of records in the authority section (We
  // don't know so 0 for now) - 16 bits.
  this->header[8] = 0x00;
  this->header[9] = 0x00;
  // Additional record count - number of records in the additional section (We
  // don't know so 0 for now) - 16 bits.
  this->header[10] = 0x00;
  this->header[11] = 0x00;

  // We've created the header so now our index is at 12.
  this->buffer_pointer = 12;
}

// ============================================================================
// DNS PACKET Question Helpers
// ============================================================================

void DNSPacket::copy_question_section() {
  unsigned char high_char = this->header[4];
  unsigned char low_char = this->header[5];

  // Figure out how many questions exist by computing on high a low characters.
  this->question_count =
      DNSPacket::convert_unsigned_char_tuple_into_int(high_char, low_char);

  for (auto i = 0; i < this->question_count; i++) {
    copy_question();
  }
}

void DNSPacket::copy_question() {
  std::vector<unsigned char> domain_vector = copy_domain_name();

  // consume 4 more bytes:
  //  - 2 bytes for the type
  std::array<unsigned char, 2> type;
  for (auto i = 0; i < 2; i++) {
    char buffer_item = this->buffer[this->buffer_pointer];
    type[i] = buffer_item;
    this->buffer_pointer++;
  }
  //  - 2 bytes for the class
  std::array<unsigned char, 2> ques_class;
  for (auto i = 0; i < 2; i++) {
    char buffer_item = this->buffer[this->buffer_pointer];
    ques_class[i] = buffer_item;
    this->buffer_pointer++;
  }

  auto question = Question(domain_vector, type, ques_class);
  this->question_vector.push_back(question);
}

// ============================================================================
// DNS PACKET Answer Helpers
// ============================================================================

void DNSPacket::copy_answer_section() {
  unsigned char high_char = this->header[6];
  unsigned char low_char = this->header[7];

  this->answer_count =
      DNSPacket::convert_unsigned_char_tuple_into_int(high_char, low_char);

  for (auto i = 0; i < this->answer_count; i++) {
    // Add domain name
    auto domain_name = copy_domain_name();
    // We'll add the type. Size of 2 bytes. Default to 1.
    std::array<unsigned char, 2> type;
    for (auto i = 0; i < type.size(); i++) {
      type[i] = buffer[this->buffer_pointer];
      this->buffer_pointer++;
    }
    //  We'll add the class. Size of 2 bytes. Default to 1.
    std::array<unsigned char, 2> ans_class;
    for (auto i = 0; i < ans_class.size(); i++) {
      ans_class[i] = buffer[this->buffer_pointer];
      this->buffer_pointer++;
    }
    // Setting TTL. Size of 4 bytes. Default to 60 seconds.
    std::array<unsigned char, 4> ttl;
    for (auto i = 0; i < ttl.size(); i++) {
      ttl[i] = buffer[this->buffer_pointer];
      this->buffer_pointer++;
    }
    // Length of Data. Size of 2 bytes.
    std::array<unsigned char, 2> length;
    for (auto i = 0; i < length.size(); i++) {
      length[i] = buffer[this->buffer_pointer];
      this->buffer_pointer++;
    }
    // Data. Variable size. Read from buffer based on length field.
    std::vector<unsigned char> data;
    int data_length = convert_unsigned_char_tuple_into_int(length[0], length[1]);
    for (auto j = 0; j < data_length; j++) {
      data.push_back(buffer[this->buffer_pointer]);
      this->buffer_pointer++;
    }

    auto answer = Answer(domain_name, type, ans_class, ttl, length, data);
    answer_vector.push_back(answer);
  }
}

// For now, we are only answering with a single answer.
void DNSPacket::create_answer_section() {
  for (auto i = 0; i < this->question_count; i++) {
    // Add domain name for the first question and so on
    auto domain_name = this->question_vector[i].get_domain_name();

    // We'll add the type. Size of 2 bytes. Default to 1.
    std::array<unsigned char, 2> type {0x00, 0x01};
    
    //  We'll add the class. Size of 2 bytes. Default to 1.
    std::array<unsigned char, 2> ans_class {0x00, 0x01};
  
    // Setting TTL. Size of 4 bytes. Default to 60 seconds.
    std::array<unsigned char, 4> ttl {0x00, 0x00, 0x00, 0x3c};
    
    // Length of Data. Size of 2 bytes. Default to 4.
    std::array<unsigned char, 2> length {0x00, 0x04};
    
    // Data. Variable size. Default to an IP address (8.8.8.8).
    std::vector<unsigned char> data;
    for (auto j = 0; j < 4; j++) {
      data.push_back(0x08);
    }

    auto answer = Answer(domain_name, type, ans_class, ttl, length, data);
    answer_vector.push_back(answer);
  }
}

void DNSPacket::create_answer_section_with_forwarding_address(sockaddr_in forwarding_address) {
  for (auto i = 0; i < this->question_count; i++) {
    // Create a new socket for forwarding
    int forwardSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (forwardSocket == -1) {
      perror("Failed to create forward socket");
      continue;
    }

    int bytesRead;
    char buffer[BUFFER_SIZE];
    socklen_t serverAddrLen = sizeof(forwarding_address);

    auto question = this->question_vector[i];
    auto packet = create_question_packet(question);

    // Forward packet
    ssize_t sent_bytes = sendto(forwardSocket, packet.data(), packet.size(), 0, reinterpret_cast<struct sockaddr *>(&forwarding_address), sizeof(forwarding_address));
    if (sent_bytes == -1) {
      perror("Failed to send forward query");
      close(forwardSocket);
      continue;
    }
    std::cout << "Sent " << sent_bytes << " bytes to forwarder" << std::endl;

    // Listen to response
    bytesRead = recvfrom(forwardSocket, buffer, sizeof(buffer), 0,
    reinterpret_cast<struct sockaddr *>(&forwarding_address),
    &serverAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data from forward server");
      close(forwardSocket);
      break;
    }
    buffer[bytesRead] = '\0';

    std::cout << "Received " << bytesRead << " forwarding bytes: " << buffer << std::endl;

    // Parse response
    DNSPacket server_response_packet = DNSPacket(buffer);
    // std::cout << "Forwarder response: " << std::endl;
    // server_response_packet.print_dns_packet();
    auto server_response_answer_section = server_response_packet.get_answer_section();

    if (server_response_answer_section.size() >= 1) {
      // Add all answers from the forwarding server
      for (const auto& server_answer : server_response_answer_section) {
        this->answer_vector.push_back(server_answer);
      }
    }

    close(forwardSocket);
  }
}

// ============================================================================
// DNS PACKET Response Helpers
// ============================================================================

DNSPacket DNSPacket::respond_to_packet(DNSPacket packet) {
  auto response_packet = DNSPacket();
  response_packet.mutate_for_response(packet);
  return response_packet;
}

void DNSPacket::mutate_for_response(DNSPacket packet) {
  auto buffer_vector = packet.get_packet_vector();

  char buffer[BUFFER_SIZE];
  auto buffer_data = buffer_vector.data();
  for (auto i = 0; i < BUFFER_SIZE; i++) {
    buffer[i] = buffer_data[i];
  }

  this->buffer_pointer = 0;
  copy_buffer(buffer);
  create_header();
  copy_question_section();
  create_answer_section();
}

DNSPacket DNSPacket::forward_packet(DNSPacket packet, sockaddr_in forwarding_address) {
  auto response_packet = DNSPacket();
  response_packet.mutate_for_forward_response(packet, forwarding_address);
  return response_packet;
}

void DNSPacket::mutate_for_forward_response(DNSPacket packet, sockaddr_in forwarding_address) {
  auto buffer_vector = packet.get_packet_vector();

  char buffer[BUFFER_SIZE];
  auto buffer_data = buffer_vector.data();
  for (auto i = 0; i < BUFFER_SIZE; i++) {
    buffer[i] = buffer_data[i];
  }

  this->buffer_pointer = 0;
  copy_buffer(buffer);
  create_header();
  copy_question_section();
  create_answer_section_with_forwarding_address(forwarding_address);
}

// ============================================================================
// DNS PACKET Utility Helpers
// ============================================================================

void DNSPacket::copy_pointer(std::vector<unsigned char> &domain_vector, int pointer_loc) {
  unsigned char buffer_item = this->buffer[pointer_loc];
  while (buffer_item != 0x00) {
    domain_vector.push_back(buffer_item);
    pointer_loc++;
    buffer_item = this->buffer[pointer_loc];
  }
  // The 0x00 - the null byte that indicates that the
  // domain name has ended.
  domain_vector.push_back(buffer_item);
}

std::vector<unsigned char> DNSPacket::copy_domain_name() {
  std::vector<unsigned char> domain_vector;
  // We're going to copy over the domain name
  unsigned char buffer_item = this->buffer[this->buffer_pointer];

  while (buffer_item != 0x00) {
    // Check if buffer_item is a pointer. Pointers begin with two filled in bits:
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | 1  1|                OFFSET                   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    auto pointer_flag = 0xc0;
    unsigned char buffer_item_flag = buffer_item & pointer_flag;
    bool is_merged_item_in_pointer_format = (buffer_item_flag ^ 0xc0) == 0x00;

    if (is_merged_item_in_pointer_format) {
      auto pointer_offset = buffer_item & 0x3F;
      auto next_offset = this->buffer[this->buffer_pointer + 1];
      int pointer_loc = convert_unsigned_char_tuple_into_int(pointer_offset, next_offset);
      copy_pointer(domain_vector, pointer_loc);
      // pass this pointer, the next (which is part of the pointer computation), and finish on the next.
      this->buffer_pointer += 2;
    } else {
      domain_vector.push_back(buffer_item);
      this->buffer_pointer++;
    }

    buffer_item = this->buffer[this->buffer_pointer];
  }

  // The 0x00 - the null byte that indicates that the
  // domain name has ended.
  domain_vector.push_back(buffer_item);
  this->buffer_pointer++;

  return domain_vector;
}

int DNSPacket::convert_unsigned_char_tuple_into_int(unsigned char char_one,
                                                    unsigned char char_two) {
  return ((int)char_one << 8) | char_two;
}

// ============================================================================
// DNS PACKET PRINT HELPERS
// ============================================================================

// Helper: Convert domain name label sequence to readable string
static std::string label_to_string(const std::vector<unsigned char>& label_sequence) {
  std::string domain_name = "";
  size_t i = 0;

  while (i < label_sequence.size() && label_sequence[i] != 0x00) {
    unsigned char length = label_sequence[i];
    i++;

    if (i + length > label_sequence.size()) {
      break;
    }

    for (unsigned char j = 0; j < length; j++) {
      domain_name += static_cast<char>(label_sequence[i]);
      i++;
    }

    if (i < label_sequence.size() && label_sequence[i] != 0x00) {
      domain_name += ".";
    }
  }

  return domain_name;
}

// Helper: Get DNS type as string
static std::string type_to_string(unsigned char high, unsigned char low) {
  int type_value = DNSPacket::convert_unsigned_char_tuple_into_int(high, low);

  switch (type_value) {
    case 1: return "A (IPv4 address)";
    case 2: return "NS (Name Server)";
    case 5: return "CNAME (Canonical Name)";
    case 6: return "SOA (Start of Authority)";
    case 15: return "MX (Mail Exchange)";
    case 16: return "TXT (Text)";
    case 28: return "AAAA (IPv6 address)";
    default: return "Unknown (" + std::to_string(type_value) + ")";
  }
}

// Helper: Get DNS class as string
static std::string class_to_string(unsigned char high, unsigned char low) {
  int class_value = DNSPacket::convert_unsigned_char_tuple_into_int(high, low);

  switch (class_value) {
    case 1: return "IN (Internet)";
    case 2: return "CS (CSNET)";
    case 3: return "CH (CHAOS)";
    case 4: return "HS (Hesiod)";
    default: return "Unknown (" + std::to_string(class_value) + ")";
  }
}

// Print the DNS Header
void DNSPacket::print_header() {
  std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
  std::cout << "║                        DNS PACKET HEADER                       ║" << std::endl;
  std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;

  // Packet ID
  int packet_id = convert_unsigned_char_tuple_into_int(header[0], header[1]);
  std::cout << "Transaction ID:      0x" << std::hex << packet_id << std::dec << " (" << packet_id << ")" << std::endl;

  // Flags (byte 2)
  bool qr = (header[2] & 0x80) != 0;
  int opcode = (header[2] & 0x78) >> 3;
  bool aa = (header[2] & 0x04) != 0;
  bool tc = (header[2] & 0x02) != 0;
  bool rd = (header[2] & 0x01) != 0;

  std::cout << "Flags:" << std::endl;
  std::cout << "  QR (Query/Response): " << (qr ? "Response (1)" : "Query (0)") << std::endl;
  std::cout << "  OPCODE:              " << opcode << " (";
  switch (opcode) {
    case 0: std::cout << "Standard Query"; break;
    case 1: std::cout << "Inverse Query"; break;
    case 2: std::cout << "Status Request"; break;
    default: std::cout << "Reserved"; break;
  }
  std::cout << ")" << std::endl;
  std::cout << "  AA (Authoritative):  " << (aa ? "Yes (1)" : "No (0)") << std::endl;
  std::cout << "  TC (Truncated):      " << (tc ? "Yes (1)" : "No (0)") << std::endl;
  std::cout << "  RD (Recursion Des.): " << (rd ? "Yes (1)" : "No (0)") << std::endl;

  // Flags (byte 3)
  bool ra = (header[3] & 0x80) != 0;
  int rcode = header[3] & 0x0F;

  std::cout << "  RA (Recursion Avl.): " << (ra ? "Yes (1)" : "No (0)") << std::endl;
  std::cout << "  RCODE:               " << rcode << " (";
  switch (rcode) {
    case 0: std::cout << "No Error"; break;
    case 1: std::cout << "Format Error"; break;
    case 2: std::cout << "Server Failure"; break;
    case 3: std::cout << "Name Error"; break;
    case 4: std::cout << "Not Implemented"; break;
    case 5: std::cout << "Refused"; break;
    default: std::cout << "Reserved"; break;
  }
  std::cout << ")" << std::endl;

  // Counts
  int qdcount = convert_unsigned_char_tuple_into_int(header[4], header[5]);
  int ancount = convert_unsigned_char_tuple_into_int(header[6], header[7]);
  int nscount = convert_unsigned_char_tuple_into_int(header[8], header[9]);
  int arcount = convert_unsigned_char_tuple_into_int(header[10], header[11]);

  std::cout << "\nRecord Counts:" << std::endl;
  std::cout << "  Questions:           " << qdcount << std::endl;
  std::cout << "  Answers:             " << ancount << std::endl;
  std::cout << "  Authority Records:   " << nscount << std::endl;
  std::cout << "  Additional Records:  " << arcount << std::endl;
  std::cout << std::endl;
}

// Print all Questions
void DNSPacket::print_all_questions() {
  if (question_vector.empty()) {
    std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                       QUESTION SECTION                         ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << "  (empty)" << std::endl << std::endl;
    return;
  }

  std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
  std::cout << "║                       QUESTION SECTION                         ║" << std::endl;
  std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;

  for (size_t i = 0; i < question_vector.size(); i++) {
    std::cout << "  [Question " << (i + 1) << "]" << std::endl;

    auto domain_name = question_vector[i].get_domain_name();
    std::string domain_str = label_to_string(domain_name);
    std::cout << "    Name:   " << domain_str << std::endl;
    std::cout << "    Type:   A (IPv4 address)" << std::endl;
    std::cout << "    Class:  IN (Internet)" << std::endl;
    std::cout << std::endl;
  }
}

// Print all Answers
void DNSPacket::print_all_answers() {
  if (answer_vector.empty()) {
    std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                        ANSWER SECTION                          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << "  (empty)" << std::endl << std::endl;
    return;
  }

  std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
  std::cout << "║                        ANSWER SECTION                          ║" << std::endl;
  std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;

  for (size_t i = 0; i < answer_vector.size(); i++) {
    std::cout << "  [Answer " << (i + 1) << "]" << std::endl;

    // Domain Name
    auto domain_name = answer_vector[i].get_domain_name();
    std::string domain_str = label_to_string(domain_name);
    std::cout << "    Name:        " << domain_str << std::endl;

    // Type
    auto type = answer_vector[i].get_type();
    std::cout << "    Type:        " << type_to_string(type[0], type[1]) << std::endl;

    // Class
    auto ans_class = answer_vector[i].get_ans_class();
    std::cout << "    Class:       " << class_to_string(ans_class[0], ans_class[1]) << std::endl;

    // TTL
    auto ttl = answer_vector[i].get_ttl();
    int ttl_value = (ttl[0] << 24) | (ttl[1] << 16) | (ttl[2] << 8) | ttl[3];
    std::cout << "    TTL:         " << ttl_value << " seconds" << std::endl;

    // Data Length
    auto length = answer_vector[i].get_length();
    int length_value = convert_unsigned_char_tuple_into_int(length[0], length[1]);
    std::cout << "    Data Length: " << length_value << " bytes" << std::endl;

    // Data
    auto data = answer_vector[i].get_data();
    int type_value = convert_unsigned_char_tuple_into_int(type[0], type[1]);

    if (type_value == 1 && data.size() == 4) {
      // A record - IPv4 address
      std::cout << "    Data:        "
                << static_cast<int>(data[0]) << "."
                << static_cast<int>(data[1]) << "."
                << static_cast<int>(data[2]) << "."
                << static_cast<int>(data[3]) << std::endl;
    } else if (type_value == 28 && data.size() == 16) {
      // AAAA record - IPv6 address
      std::cout << "    Data:        ";
      for (size_t j = 0; j < data.size(); j += 2) {
        printf("%02x%02x", data[j], data[j+1]);
        if (j < data.size() - 2) std::cout << ":";
      }
      std::cout << std::endl;
    } else {
      // Other types - hex
      std::cout << "    Data:        ";
      for (size_t j = 0; j < data.size(); j++) {
        printf("%02x ", data[j]);
      }
      std::cout << std::endl;
    }
    std::cout << std::endl;
  }
}

// Print the entire DNS Packet
void DNSPacket::print_dns_packet() {
  std::cout << "\n";
  std::cout << "================================================================" << std::endl;
  std::cout << "                    DNS PACKET DETAILS                          " << std::endl;
  std::cout << "================================================================" << std::endl;
  std::cout << std::endl;

  print_header();
  print_all_questions();
  print_all_answers();

  std::cout << "================================================================" << std::endl;
  std::cout << "                       END OF DNS PACKET                        " << std::endl;
  std::cout << "================================================================" << std::endl;
  std::cout << "\n";
}