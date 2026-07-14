#pragma once

#include <sqlite3.h>

#include <string>
#include <vector>

struct Note {
  int id;
  std::string content;
  std::string created_at;
};

class Database {
 public:
  Database();
  ~Database();

  bool open(const std::string& db_path, std::string& error_message);
  void close();
  bool migrate(std::string& error_message);

  bool create_user(const std::string& username,
                   const std::string& salt_hex,
                   const std::string& password_hash_hex,
                   std::string& error_message);

  bool get_user_auth_data(const std::string& username,
                          int& user_id,
                          std::string& salt_hex,
                          std::string& password_hash_hex,
                          std::string& error_message);

  bool save_session(const std::string& token,
                    int user_id,
                    long long expires_at,
                    std::string& error_message);

  bool get_session(const std::string& token,
                   int& user_id,
                   long long& expires_at,
                   std::string& error_message);

  bool delete_session(const std::string& token, std::string& error_message);
  bool delete_expired_sessions(std::string& error_message);

  bool add_note(int user_id, const std::string& content, std::string& error_message);
  bool get_notes_for_user(int user_id, std::vector<Note>& notes, std::string& error_message);

 private:
  sqlite3* db_;
};
