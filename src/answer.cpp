#include "answer.h"
#include <vector>
// #include <iostream>

Answer::Answer(std::vector<unsigned char> domain_name,
               std::array<unsigned char, 2> type,
               std::array<unsigned char, 2> ans_class,
               std::array<unsigned char, 4> ttl,
               std::array<unsigned char, 2> length,
               std::vector<unsigned char> data) {
  this->domain_name = domain_name;
  this->type = type;
  this->ans_class = ans_class;
  this->ttl = ttl;
  this->length = length;
  this->data = data;
}

void Answer::add_answer_into_return_packet(std::vector<unsigned char>* return_packet) {
  // Copy in the domain name first
  for (auto domain_char : this->domain_name) {
    return_packet->push_back(domain_char);
  }

  // Copy in the type
  return_packet->push_back(this->type[0]);
  return_packet->push_back(this->type[1]);

  // Copy in the class
  return_packet->push_back(this->ans_class[0]);
  return_packet->push_back(this->ans_class[1]);

  // Copy in the ttl
  return_packet->push_back(this->ttl[1]);
  return_packet->push_back(this->ttl[0]);
  return_packet->push_back(this->ttl[2]);
  return_packet->push_back(this->ttl[3]);

  // Copy in the length
  return_packet->push_back(this->length[0]);
  return_packet->push_back(this->length[1]);

  // Copy data
  for (auto data_char : this->data) {
    return_packet->push_back(data_char);
  }
}