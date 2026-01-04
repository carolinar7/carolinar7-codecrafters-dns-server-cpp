#include <array>
#include <vector>

class Question {
private:
  std::vector<unsigned char> domain_name;
  std::array<unsigned char, 2> type;
  std::array<unsigned char, 2> ques_class;

public:
  Question(std::vector<unsigned char> domain_name,
         std::array<unsigned char, 2> type,
         std::array<unsigned char, 2> ques_class);

  void add_question_into_return_packet(std::vector<unsigned char>* return_packet);

  std::vector<unsigned char> get_domain_name();
};