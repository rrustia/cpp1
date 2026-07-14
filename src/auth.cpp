#include "auth.hpp"

#include <CommonCrypto/CommonDigest.h>

#include <chrono>
#include <cctype>
#include <fstream>
#include <random>
#include <sstream>
#include <vector>

namespace {

std::string to_hex(const std::vector<unsigned char>& bytes) {
  // I convert raw bytes to a text form so I can safely store hash and salt values in SQLite.
  static const char* hex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char b : bytes) {
    out.push_back(hex[(b >> 4) & 0x0F]);
    out.push_back(hex[b & 0x0F]);
  }
  return out;
}

std::vector<unsigned char> sha256_bytes(const std::string& input) {
  // I keep hashing in one helper so password code stays clean and easy to follow.
  std::vector<unsigned char> digest(CC_SHA256_DIGEST_LENGTH);
  CC_SHA256(input.data(), static_cast<CC_LONG>(input.size()), digest.data());
  return digest;
}

bool constant_time_equals(const std::string& a, const std::string& b) {
  // I compare hashes in constant time so timing differences leak less information.
  // This pattern is safer than returning immediately when the first mismatch appears.
  if (a.size() != b.size()) {
    return false;
  }

  unsigned char result = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    result |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return result == 0;
}

}  // namespace

bool AuthService::validate_username(const std::string& username, std::string& error_message) {
  // I keep username rules simple so beginners can understand and adjust them.
  if (username.size() < 3 || username.size() > 32) {
    error_message = "Username must be between 3 and 32 characters";
    return false;
  }

  for (char ch : username) {
    if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '_')) {
      error_message = "Username can only contain letters, numbers, and underscore";
      return false;
    }
  }

  return true;
}

bool AuthService::validate_password(const std::string& password, std::string& error_message) {
  // I require a minimum length for basic strength without making this demo complex.
  if (password.size() < 8) {
    error_message = "Password must be at least 8 characters";
    return false;
  }
  return true;
}

std::string AuthService::generate_hex_random(std::size_t byte_count) {
  // I prefer /dev/urandom on macOS because it is cryptographically secure.
  std::vector<unsigned char> bytes(byte_count);
  std::ifstream random_stream("/dev/urandom", std::ios::binary);
  if (random_stream.good()) {
    random_stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(byte_count));
    if (random_stream.gcount() == static_cast<std::streamsize>(byte_count)) {
      return to_hex(bytes);
    }
  }

  // I still provide a fallback so the app does not crash if random source is unavailable.
  std::random_device rd;
  for (std::size_t i = 0; i < byte_count; ++i) {
    bytes[i] = static_cast<unsigned char>(rd() & 0xFF);
  }
  return to_hex(bytes);
}

std::string AuthService::hash_password(const std::string& password, const std::string& salt_hex) {
  // I run many SHA256 rounds so brute force is harder than a single hash.
  // I use a deterministic algorithm here so login can recompute the same result later.
  std::string state = salt_hex + password;
  std::vector<unsigned char> digest = sha256_bytes(state);

  const int rounds = 100000;
  for (int i = 0; i < rounds; ++i) {
    const std::string round_input = to_hex(digest) + salt_hex;
    digest = sha256_bytes(round_input);
  }

  return to_hex(digest);
}

bool AuthService::register_user(Database& db,
                                const std::string& username,
                                const std::string& password,
                                std::string& error_message) {
  // I validate inputs early so I never write invalid credentials to the database.
  if (!validate_username(username, error_message) ||
      !validate_password(password, error_message)) {
    return false;
  }

  const std::string salt_hex = generate_hex_random(16);
  const std::string hash_hex = hash_password(password, salt_hex);

  return db.create_user(username, salt_hex, hash_hex, error_message);
}

bool AuthService::login(Database& db,
                        const std::string& username,
                        const std::string& password,
                        std::string& token,
                        std::string& error_message) {
  // I read salt and expected hash from the user record.
  // Then I hash the provided password again and compare both hashes.
  int user_id = 0;
  std::string salt_hex;
  std::string expected_hash_hex;
  if (!db.get_user_auth_data(username, user_id, salt_hex, expected_hash_hex, error_message)) {
    return false;
  }

  const std::string computed_hash_hex = hash_password(password, salt_hex);
  if (!constant_time_equals(computed_hash_hex, expected_hash_hex)) {
    error_message = "Invalid username or password";
    return false;
  }

  token = generate_hex_random(32);
  // I set a one day expiration so tokens are not valid forever.
  const auto now = std::chrono::system_clock::now();
  const auto expires = now + std::chrono::hours(24);
  const auto expires_unix =
      std::chrono::duration_cast<std::chrono::seconds>(expires.time_since_epoch()).count();

  if (!db.save_session(token, user_id, expires_unix, error_message)) {
    return false;
  }

  return true;
}

bool AuthService::authenticate_token(Database& db,
                                     const std::string& token,
                                     int& user_id,
                                     std::string& error_message) {
  // I treat an empty token as unauthorized immediately to avoid unnecessary database work.
  if (token.empty()) {
    error_message = "Missing token";
    return false;
  }

  long long expires_at = 0;
  if (!db.get_session(token, user_id, expires_at, error_message)) {
    return false;
  }

  const auto now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();

  if (expires_at <= now_unix) {
    db.delete_session(token, error_message);
    error_message = "Session expired";
    return false;
  }

  return true;
}
