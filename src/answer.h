#include <array>
#include <vector>

class Answer {
private:
  std::vector<unsigned char> domain_name;
  std::array<unsigned char, 2> type;
  std::array<unsigned char, 2> ans_class;
  std::array<unsigned char, 4> ttl;
  std::array<unsigned char, 2> length;
  std::vector<unsigned char> data;

public:
  Answer(std::vector<unsigned char> domain_name,
         std::array<unsigned char, 2> type,
         std::array<unsigned char, 2> ans_class,
         std::array<unsigned char, 4> ttl, std::array<unsigned char, 2> length,
         std::vector<unsigned char> data);

  void add_answer_into_return_packet(std::vector<unsigned char>* return_packet);
  std::vector<unsigned char> get_data();
  std::vector<unsigned char> get_domain_name();
  std::array<unsigned char, 2> get_type();
  std::array<unsigned char, 2> get_ans_class();
  std::array<unsigned char, 4> get_ttl();
  std::array<unsigned char, 2> get_length();
};