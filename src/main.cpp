#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  // Disable output buffering
  setbuf(stdout, NULL);

  // You can use print statements as follows for debugging, they'll be visible
  // when running tests.
  std::cout << "Logs from your program will appear here!" << std::endl;

  int udpSocket;
  struct sockaddr_in clientAddress;

  udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSocket == -1) {
    std::cerr << "Socket creation failed: " << strerror(errno) << "..."
              << std::endl;
    return 1;
  }

  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
      0) {
    std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
    return 1;
  }

  sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(2053),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr),
           sizeof(serv_addr)) != 0) {
    std::cerr << "Bind failed: " << strerror(errno) << std::endl;
    return 1;
  }

  int bytesRead;
  char buffer[512];
  socklen_t clientAddrLen = sizeof(clientAddress);

  while (true) {
    // Receive data
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         reinterpret_cast<struct sockaddr *>(&clientAddress),
                         &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }

    buffer[bytesRead] = '\0';
    std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;

    // Create 12 byte response
    unsigned char response[12];

    // Packet Identifier (ID) - same as ID of query packet - 16 bit.
    response[0] = buffer[0];
    response[1] = buffer[1];
    // The rest should fit in 8 bits.
    // Query/Response Indicator (QR) - One is for a reply packet - 1 bit.
    // OP Code - Zero is a standard lookup / query - 4 bits.
    // Authoritive Answer - Zero since we don't own the the domain - 1 bit.
    // Truncation - UDP response so always 0 - 1 bit.
    // Recursion Desired - Zero since this is a server - 1 bit.
    response[2] = 0x0F;
    // Recursion Available - Zero since it's not available - 1 bit.
    // Reserved - Not used, so zero - 3 bits.
    // Response Code - status of the response zero (no error) - 4 bits.
    response[3] = 0x00;
    // Question count - number of questions in the question section. (We don't know so 0 for now) - 16 bits.
    response[4] = 0x00;
    response[5] = 0x00;
    // Answer Record count - number of records in the answer section (We don't know so 0 for now) - 16 bits.
    response[6] = 0x00;
    response[7] = 0x00;
    // Authority Record count - number of records in the authority section (We don't know so 0 for now) - 16 bits.
    response[8] = 0x00;
    response[9] = 0x00;
    // Additional record count - number of records in the additional section (We don't know so 0 for now) - 16 bits.
    response[10] = 0x00;
    response[11] = 0x00;

    // Send response
    if (sendto(udpSocket, response, sizeof(response), 0,
               reinterpret_cast<struct sockaddr *>(&clientAddress),
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);

  return 0;
}
