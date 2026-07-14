#pragma once

#include <string>

#include "database.hpp"

class AuthService {
 public:
  bool register_user(Database& db,
                     const std::string& username,
                     const std::string& password,
                     std::string& error_message);

  bool login(Database& db,
             const std::string& username,
             const std::string& password,
             std::string& token,
             std::string& error_message);

  bool authenticate_token(Database& db,
                          const std::string& token,
                          int& user_id,
                          std::string& error_message);

 private:
  bool validate_username(const std::string& username, std::string& error_message);
  bool validate_password(const std::string& password, std::string& error_message);

  std::string generate_hex_random(std::size_t byte_count);
  std::string hash_password(const std::string& password, const std::string& salt_hex);
};
