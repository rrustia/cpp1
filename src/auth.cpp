#include "auth.hpp"

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#endif

#include <chrono>
#include <cctype>
#include <fstream>
#include <random>
#include <sstream>
#include <vector>

namespace {

std::string to_hex(const std::vector<unsigned char>& bytes) {
  // Converts raw bytes into a lowercase hex string so hash and salt values can be safely stored as text.
  // Input: bytes is the raw byte data to encode.
  // Output: Returns a hex string that is exactly twice the length of the input.
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
  // Runs a single SHA256 hash on an input string and returns the raw digest bytes.
  // Input: input is the string to hash.
  // Output: Returns a 32-byte vector with the SHA256 result.
#if defined(__APPLE__)
  std::vector<unsigned char> digest(CC_SHA256_DIGEST_LENGTH);
  CC_SHA256(input.data(), static_cast<CC_LONG>(input.size()), digest.data());
  return digest;
#elif defined(_WIN32)
  std::vector<unsigned char> digest(32);

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD bytes_written = 0;
  std::vector<unsigned char> hash_object;

  if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
          &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
    return {};
  }

  if (!BCRYPT_SUCCESS(BCryptGetProperty(
          algorithm,
          BCRYPT_OBJECT_LENGTH,
          reinterpret_cast<PUCHAR>(&object_size),
          static_cast<ULONG>(sizeof(object_size)),
          &bytes_written,
          0))) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }

  hash_object.resize(object_size);
  if (!BCRYPT_SUCCESS(BCryptCreateHash(
          algorithm,
          &hash,
          hash_object.data(),
          object_size,
          nullptr,
          0,
          0))) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }

  if (!BCRYPT_SUCCESS(BCryptHashData(
          hash,
          reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
          static_cast<ULONG>(input.size()),
          0)) ||
      !BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0))) {
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return {};
  }

  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return digest;
#else
  return {};
#endif
}

bool constant_time_equals(const std::string& a, const std::string& b) {
  // Compares two strings without stopping early on a mismatch, which reduces timing-based information leaks.
  // Early returns could let an attacker guess hash values from how fast the server responds.
  // Input: a and b are the two strings to compare.
  // Output: Returns true only if both strings are identical in length and content.
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
  // Checks that a username is between 3 and 32 characters and contains only letters, numbers, or underscores.
  // Input: username is the value to check, error_message is filled with a reason if the check fails.
  // Output: Returns true if the username passes all rules.
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
  // Checks that a password is at least 8 characters long.
  // Input: password is the value to check, error_message is filled if it is too short.
  // Output: Returns true if the password meets the minimum length.
  if (password.size() < 8) {
    error_message = "Password must be at least 8 characters";
    return false;
  }
  return true;
}

std::string AuthService::generate_hex_random(std::size_t byte_count) {
  // Generates a random byte sequence using the system's cryptographically secure random source.
  // Input: byte_count is how many random bytes to produce.
  // Output: Returns a hex string of length byte_count times two.
  std::vector<unsigned char> bytes(byte_count);
#if defined(_WIN32)
  if (BCRYPT_SUCCESS(BCryptGenRandom(
          nullptr,
          bytes.data(),
          static_cast<ULONG>(byte_count),
          BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
    return to_hex(bytes);
  }
#endif

  std::ifstream random_stream("/dev/urandom", std::ios::binary);
  if (random_stream.good()) {
    random_stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(byte_count));
    if (random_stream.gcount() == static_cast<std::streamsize>(byte_count)) {
      return to_hex(bytes);
    }
  }

  // Falls back to std::random_device if the system random source was not available.
  std::random_device rd;
  for (std::size_t i = 0; i < byte_count; ++i) {
    bytes[i] = static_cast<unsigned char>(rd() & 0xFF);
  }
  return to_hex(bytes);
}

std::string AuthService::hash_password(const std::string& password, const std::string& salt_hex) {
  // Hashes a password by combining it with the salt and running many SHA256 rounds.
  // Running many rounds makes brute force significantly slower than a single hash.
  // The process is deterministic so the same password and salt always produce the same result.
  // Input: password is the plain text, salt_hex is the hex-encoded salt for this user.
  // Output: Returns the final hash as a hex string.
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
  // Registers a new user by validating credentials, generating a random salt, hashing the password, and saving everything to the database.
  // Input: db is the database connection, username and password are the new account details. error_message is filled on failure.
  // Output: Returns true if the account was created successfully.
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
  // Logs a user in by loading their stored salt and hash, recomputing the hash from the given password, and comparing the two.
  // On success a random session token is generated and stored in the database.
  // Input: db is the database connection, username and password are the login credentials. token is filled on success. error_message is filled on failure.
  // Output: Returns true if credentials matched and a session was saved.
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
  // Sets a 24-hour expiry on the new session so tokens do not remain valid indefinitely.
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
  // Checks that a token exists in the database and has not expired yet.
  // An empty token is rejected straight away without touching the database.
  // Input: db is the database connection, token is the bearer token to validate. user_id is filled on success. error_message is filled on failure.
  // Output: Returns true if the token is valid and the session is still active.
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
