
#include "dns_packet.h"
#include <array>
#include <vector>
// #include <iostream>

DNSPacket::DNSPacket(char buf[512]) {
  for (int i = 0; i < 512; i++) {
    this->buffer[i] = buf[i];
  }
  this->buffer_pointer = 0;
  create_initial_dns_packet();
}

void DNSPacket::create_initial_dns_packet() {
  DNSPacket::create_header();
  DNSPacket::create_question_section();
}

std::vector<unsigned char> DNSPacket::get_return_packet() {
  std::vector<unsigned char> return_packet;

  // Header section
  for (auto i = 0; i < this->header.size(); i++) {
    return_packet.push_back(this->header[i]);
  }

  // Question section
  for (auto i = 0; i < this->question_vector.size(); i++) {
    return_packet.push_back(this->question_vector[i]);
  }

  return return_packet;
}

int DNSPacket::convert_unsigned_char_tuple_into_int(unsigned char char_one, unsigned char char_two) {
  return ((int)char_one << 8) | char_two;
}

void DNSPacket::create_header() {
  // Create 12 byte response
  // Packet Identifier (ID) - same as ID of query packet - 16 bit.
  this->header[0] = buffer[0];
  this->header[1] = buffer[1];
  // The rest should fit in 8 bits.
  // Query/Response Indicator (QR) - One is for a reply packet - 1 bit.
  // OP Code - Zero is a standard lookup / query - 4 bits.
  // Authoritive Answer - Zero since we don't own the the domain - 1 bit.
  // Truncation - UDP response so always 0 - 1 bit.
  // Recursion Desired - Zero since this is a server - 1 bit.
  this->header[2] = 0x80;
  // Recursion Available - Zero since it's not available - 1 bit.
  // Reserved - Not used, so zero - 3 bits.
  // Response Code - status of the response zero (no error) - 4 bits.
  this->header[3] = 0x00;
  // Question count - number of questions in the question section. (We don't
  // know so 0 for now) - 16 bits.
  this->header[4] = buffer[4];
  this->header[5] = buffer[5];
  // Answer Record count - number of records in the answer section (We don't
  // know so 0 for now) - 16 bits.
  this->header[6] = 0x00;
  this->header[7] = 0x00;
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
  this->question_count = DNSPacket::convert_unsigned_char_tuple_into_int(high_char, low_char);

  for (auto i = 0; i < this->question_count; i++) {
    copy_question();
  }
}

void DNSPacket::copy_question() {
  // We're going to copy over the domain name
  char buffer_item = this->buffer[this->buffer_pointer];

  while (buffer_item != 0x00) {
    this->question_vector.push_back(buffer_item);
    this->buffer_pointer++;
    buffer_item = this->buffer[this->buffer_pointer];
  }
  // The 0x00 - the null byte that indicates that the
  // domain name has ended.
  this->question_vector.push_back(buffer_item);
  this->buffer_pointer++;

  // consume 4 more bytes:
  //  - 2 bytes for the type
  //  - 2 bytes for the class
  for (auto i = 0; i < 4; i++) {
    char buffer_item = this->buffer[this->buffer_pointer];
    this->question_vector.push_back(buffer_item);
    this->buffer_pointer++;
  }
}