#include "dns_packet.h"
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <ostream>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <memory>
#include <stdlib.h>

std::string RESOLVER_FLAG = "--resolver";
std::string ADDRESS_DELIMETER = ":";

std::unique_ptr<sockaddr_in> make_sockaddr(const std::string &ip_address_str,
                          const std::string &port_address_str) {
  auto port_address = std::stoi(port_address_str);
  auto unasigned_int_port_address = static_cast<uint16_t>(port_address);
  auto addr = std::make_unique<sockaddr_in>();
  addr->sin_family = AF_INET;
  addr->sin_port = htons(unasigned_int_port_address);

  if (inet_pton(AF_INET, ip_address_str.c_str(), &addr->sin_addr) != 1) {
    throw std::runtime_error("Invalid IPv4 address");
  }

  return addr;
}

int main(int argc, char *argv[]) {
  std::string ip_address_str = "";
  std::string port_address_str = "";

  // When an argument is passed we expect to forward our packet.
  if (argc > 1) {
    if (argc != 3) {
      // We should only expect two arguments in addition.
      throw std::runtime_error(
          "Expected two arguments. The --resolver flag and the address.");
    }

    if (std::strcmp(RESOLVER_FLAG.c_str(), argv[1]) != 0) {
      // We should have expected the resolver flag
      throw std::runtime_error("Expected the --resolver flag.");
    }

    std::string forward_address = argv[2];
    auto delimeter_location = forward_address.find(ADDRESS_DELIMETER);

    if (delimeter_location == std::string::npos) {
      // The delimeter location was not found.
      throw std::runtime_error(
          "There was an error parsing the forwarding address.");
    }

    ip_address_str = forward_address.substr(0, delimeter_location);
    port_address_str =
        forward_address.substr(delimeter_location + 1, forward_address.size());

    std::cout << "Forwarding to address with ip " << ip_address_str
              << " and port " << port_address_str << std::endl;
  }

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

    auto packet_received = DNSPacket(buffer);
    // std::cout << "Packet Received: " << std::endl;
    // packet_received.print_dns_packet();

    auto forward_sockaddr = *make_sockaddr(ip_address_str, port_address_str).release();

    DNSPacket response_packet =
        (!ip_address_str.empty() && !port_address_str.empty())
            ? DNSPacket::forward_packet(packet_received, forward_sockaddr)
            : DNSPacket::respond_to_packet(packet_received);
    // std::cout << "Response from this server: " << std::endl;
    // response_packet.print_dns_packet();
    std::vector<unsigned char> response = response_packet.get_packet_vector();

    // Send response
    if (sendto(udpSocket, response.data(), response.size(), 0,
               reinterpret_cast<struct sockaddr *>(&clientAddress),
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);

  return 0;
}
