#include "question.h"
#include <vector>
// #include <iostream>

Question::Question(std::vector<unsigned char> domain_name,
               std::array<unsigned char, 2> type,
               std::array<unsigned char, 2> ques_class) {
  this->domain_name = domain_name;
  this->type = type;
  this->ques_class = ques_class;
}

void Question::add_question_into_return_packet(std::vector<unsigned char>* return_packet) {
  // Copy in the domain name first
  for (auto domain_char : this->domain_name) {
    return_packet->push_back(domain_char);
  }

  // Copy in the type
  return_packet->push_back(this->type[0]);
  return_packet->push_back(this->type[1]);
  
  // Copy in the class
  return_packet->push_back(this->ques_class[0]);
  return_packet->push_back(this->ques_class[1]);
}

std::vector<unsigned char> Question::get_domain_name() {
  return this->domain_name;
}