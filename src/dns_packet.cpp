
#include "dns_packet.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <string>
#include <array>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <cstring>

std::string DOMAIN_NAME = "codecrafters.io";
std::string NAME_DELIMETER = ".";

DNSPacket::DNSPacket(char buf[512]) {
  std::cout << "Normal Constructor" << std::endl;
  for (int i = 0; i < 512; i++) {
    this->buffer[i] = buf[i];
  }
  this->buffer_pointer = 0;
  create_initial_dns_packet();
}

DNSPacket::DNSPacket(char buf[512], sockaddr_in forwarding_address, int udpSocket) {
  std::cout << "Forwarding Constructor" << std::endl;
  for (int i = 0; i < 512; i++) {
    this->buffer[i] = buf[i];
  }
  this->buffer_pointer = 0;
  create_initial_dns_packet_with_forwarding_address(forwarding_address, udpSocket);
}

void DNSPacket::create_initial_dns_packet() {
  DNSPacket::create_header();
  DNSPacket::create_question_section();
  DNSPacket::create_answer_section();
}

void DNSPacket::create_initial_dns_packet_with_forwarding_address(sockaddr_in forward_address, int udpSocket) {
  DNSPacket::create_header();
  // The answer section will be filled within this method.
  DNSPacket::create_sections_with_forwarder(forward_address, udpSocket);
}

std::vector<unsigned char> DNSPacket::get_return_packet() {
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

std::vector<unsigned char> DNSPacket::get_return_packet_for_question(int index) {
  std::vector<unsigned char> return_packet;

  // Header section
  for (auto i = 0; i < this->header.size(); i++) {
    return_packet.push_back(this->header[i]);
  }

  this->question_vector[index].add_question_into_return_packet(&return_packet);

  return return_packet;
}

int DNSPacket::convert_unsigned_char_tuple_into_int(unsigned char char_one,
                                                    unsigned char char_two) {
  return ((int)char_one << 8) | char_two;
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

void DNSPacket::create_question_section() {
  unsigned char high_char = header[4];
  unsigned char low_char = header[5];

  // Figure out how many questions exist by computing on high a low characters.
  this->question_count =
      DNSPacket::convert_unsigned_char_tuple_into_int(high_char, low_char);

  for (auto i = 0; i < this->question_count; i++) {
    copy_question();
  }
}

void DNSPacket::create_sections_with_forwarder(sockaddr_in forwarding_address, int udpSocket) {
  // Let's create the question section as normal.
  create_question_section();
  // Answer section
  create_answer_section_with_forwarding_address(forwarding_address, udpSocket);
}

void DNSPacket::copy_pointer(std::vector<unsigned char> domain_vector, int pointer_loc) {
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

void DNSPacket::copy_question() {
  std::vector<unsigned char> domain_vector;
  // We're going to copy over the domain name
  unsigned char buffer_item = this->buffer[this->buffer_pointer];

  while (buffer_item != 0x00) {
    // Check if buffer_item is a pointer
    unsigned char pointer_check = buffer_item & 0xc0;
    if ((pointer_check ^ 0xc0) == 0x00) {
      // It's a pointer!
      int pointer_loc = convert_unsigned_char_tuple_into_int((buffer_item & 0x3F), this->buffer[this->buffer_pointer + 1]);
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

void DNSPacket::create_answer_section_with_forwarding_address(sockaddr_in forwarding_address, int udpSocket) {
  std::cout << "Answer section with forwarding address" << std::endl;
  for (auto i = 0; i < this->question_count; i++) {
    int bytesRead;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(forwarding_address);

    auto packet = get_return_packet_for_question(i);

    std::cout << "forwarding packet" << std::endl;
    // Forward packet
    if (sendto(udpSocket, packet.data(), packet.size(), 0, reinterpret_cast<struct sockaddr *>(&forwarding_address), sizeof(forwarding_address)) == -1) {
      perror("Failed to send response");
    }
    
    std::cout << "listening to packet" << std::endl;
    // Listen to response
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
    reinterpret_cast<struct sockaddr *>(&forwarding_address),
    &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }
    buffer[bytesRead] = '\0';

    std::cout << "Received " << bytesRead << " forwarding bytes: " << buffer << std::endl;

    // Parse response
    DNSPacket server_response_packet = DNSPacket(buffer);
    auto server_response_answer_section = server_response_packet.get_answer_section();
    // Making a VERY STRONG ASSUMPTION that there is only one answer in the packet.
    if (server_response_answer_section.size() == 1) {
      auto server_answer = server_response_answer_section[0];
      this->answer_vector.push_back(server_answer);
    } else {
      throw std::runtime_error("Did not receive an answer from server.");
    }
  }
}

std::vector<unsigned char>
DNSPacket::convert_string_to_label_sequence(std::string str) {
  std::vector<unsigned char> label_sequence;
  while (str.length() != 0) {
    auto delimeter_location = str.find(NAME_DELIMETER);
    std::string token = str.substr(0, delimeter_location);

    // Convert token to label sequence.
    // Add length
    unsigned char token_length = (unsigned char)token.length();
    label_sequence.push_back(token_length);

    // Add characters
    for (auto i = 0; i < token.length(); i++) {
      char token_char = token.at(i);
      label_sequence.push_back((unsigned char)token_char);
    }

    // Shorten string to compute the next token
    auto removal_location = delimeter_location + 1;
    if (delimeter_location == std::string::npos) {
      removal_location = str.length();
    }
    str.erase(0, removal_location);
  }
  // Null byte
  label_sequence.push_back(0x00);
  return label_sequence;
}

// ============================================================================
// DNS PACKET PRINT HELPER FUNCTIONS
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