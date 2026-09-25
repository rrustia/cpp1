#pragma once

#include <string>

#include "database.hpp"

class AuthService {
 public:
  // Registers a new user by validating credentials, generating a salt, hashing the password, and writing the record to the database.
  // Input: db is the database connection, username and password are the new account details. error_message is filled on failure.
  // Output: Returns true if the account was created successfully.
  bool register_user(Database& db,
                     const std::string& username,
                     const std::string& password,
                     std::string& error_message);

  // Verifies a username and password against the stored hash, then creates and saves a session token on success.
  // Input: db is the database connection, username and password are the login credentials. token is filled on success. error_message is filled on failure.
  // Output: Returns true if credentials matched and a session was saved.
  bool login(Database& db,
             const std::string& username,
             const std::string& password,
             std::string& token,
             std::string& error_message);

  // Checks that a bearer token exists in the database and has not expired.
  // Input: db is the database connection, token is the bearer token to validate. user_id is filled on success. error_message is filled on failure.
  // Output: Returns true if the token is valid and the session is still active.
  bool authenticate_token(Database& db,
                          const std::string& token,
                          int& user_id,
                          std::string& error_message);

 private:
  // Checks that a username is between 3 and 32 characters and uses only letters, numbers, or underscores.
  // Input: username is the value to check, error_message is filled on failure.
  // Output: Returns true if the username passes all rules.
  bool validate_username(const std::string& username, std::string& error_message);

  // Checks that a password is at least 8 characters long.
  // Input: password is the value to check, error_message is filled if it is too short.
  // Output: Returns true if the password meets the minimum length.
  bool validate_password(const std::string& password, std::string& error_message);

  // Generates a cryptographically secure random value from the system random source.
  // Input: byte_count is how many random bytes to produce.
  // Output: Returns a hex string of length byte_count times two.
  std::string generate_hex_random(std::size_t byte_count);

  // Hashes a password with a salt using many SHA256 rounds to slow down brute force attempts.
  // Input: password is the plain text, salt_hex is the hex-encoded salt for this user.
  // Output: Returns the final hash as a hex string.
  std::string hash_password(const std::string& password, const std::string& salt_hex);
};
