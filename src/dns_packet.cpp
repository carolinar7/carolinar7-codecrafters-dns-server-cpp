
#include "dns_packet.h"
#include <array>

std::array<unsigned char, 12>
DNSMessage::create_message_from_buffer(char buffer[512]) {
  // Create 12 byte response
  std::array<unsigned char, 12> response{};

  // Packet Identifier (ID) - same as ID of query packet - 16 bit.
  response[0] = buffer[0];
  response[1] = buffer[1];
  // The rest should fit in 8 bits.
  // Query/Response Indicator (QR) - One is for a reply packet - 1 bit.
  // OP Code - Zero is a standard lookup / query - 4 bits.
  // Authoritive Answer - Zero since we don't own the the domain - 1 bit.
  // Truncation - UDP response so always 0 - 1 bit.
  // Recursion Desired - Zero since this is a server - 1 bit.
  response[2] = 0x80;
  // Recursion Available - Zero since it's not available - 1 bit.
  // Reserved - Not used, so zero - 3 bits.
  // Response Code - status of the response zero (no error) - 4 bits.
  response[3] = 0x00;
  // Question count - number of questions in the question section. (We don't
  // know so 0 for now) - 16 bits.
  response[4] = 0x00;
  response[5] = 0x00;
  // Answer Record count - number of records in the answer section (We don't
  // know so 0 for now) - 16 bits.
  response[6] = 0x00;
  response[7] = 0x00;
  // Authority Record count - number of records in the authority section (We
  // don't know so 0 for now) - 16 bits.
  response[8] = 0x00;
  response[9] = 0x00;
  // Additional record count - number of records in the additional section (We
  // don't know so 0 for now) - 16 bits.
  response[10] = 0x00;
  response[11] = 0x00;

  return response;
}