#include "database.hpp"

#include <sqlite3.h>

#include <iostream>

namespace {

bool exec_sql(sqlite3* db, const char* sql, std::string& error_message) {
  // I use this small helper for schema and cleanup statements that do not need parameters.
  char* raw_error = nullptr;
  const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &raw_error);
  if (rc != SQLITE_OK) {
    error_message = raw_error ? raw_error : "Unknown SQLite error";
    sqlite3_free(raw_error);
    return false;
  }
  return true;
}

}  // namespace

Database::Database() : db_(nullptr) {}

Database::~Database() { close(); }

bool Database::open(const std::string& db_path, std::string& error_message) {
  // I open one persistent connection because this small app is single process.
  const int rc = sqlite3_open(db_path.c_str(), &db_);
  if (rc != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  if (!exec_sql(db_, "PRAGMA foreign_keys = ON;", error_message)) {
    return false;
  }

  return true;
}

void Database::close() {
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

bool Database::migrate(std::string& error_message) {
  // I keep schema creation idempotent so the app can restart safely.
  const char* sql = R"SQL(
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      salt_hex TEXT NOT NULL,
      password_hash_hex TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  )SQL";

  return exec_sql(db_, sql, error_message);
}

bool Database::create_user(const std::string& username,
                           const std::string& salt_hex,
                           const std::string& password_hash_hex,
                           std::string& error_message) {
  // I use prepared statements to avoid SQL injection and improve safety.
  // Every user value is bound as data, so input cannot break SQL structure.
  const char* sql =
      "INSERT INTO users(username, salt_hex, password_hash_hex) VALUES (?, ?, ?);";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, salt_hex.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, password_hash_hex.c_str(), -1, SQLITE_TRANSIENT);

  const int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  return true;
}

bool Database::get_user_auth_data(const std::string& username,
                                  int& user_id,
                                  std::string& salt_hex,
                                  std::string& password_hash_hex,
                                  std::string& error_message) {
  // I return only the fields needed for login to keep data flow minimal.
  const char* sql =
      "SELECT id, salt_hex, password_hash_hex FROM users WHERE username = ? LIMIT 1;";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

  const int rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    user_id = sqlite3_column_int(stmt, 0);
    const unsigned char* salt = sqlite3_column_text(stmt, 1);
    const unsigned char* hash = sqlite3_column_text(stmt, 2);
    salt_hex = salt ? reinterpret_cast<const char*>(salt) : "";
    password_hash_hex = hash ? reinterpret_cast<const char*>(hash) : "";
    sqlite3_finalize(stmt);
    return true;
  }

  sqlite3_finalize(stmt);
  if (rc == SQLITE_DONE) {
    error_message = "User not found";
    return false;
  }

  error_message = sqlite3_errmsg(db_);
  return false;
}

bool Database::save_session(const std::string& token,
                            int user_id,
                            long long expires_at,
                            std::string& error_message) {
  // I keep session data in a table so token validation is stateless for the HTTP server.
  const char* sql =
      "INSERT INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?) "
      "ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, "
      "expires_at = excluded.expires_at;";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, user_id);
  sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(expires_at));

  const int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  return true;
}

bool Database::get_session(const std::string& token,
                           int& user_id,
                           long long& expires_at,
                           std::string& error_message) {
  const char* sql = "SELECT user_id, expires_at FROM sessions WHERE token = ? LIMIT 1;";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);

  const int rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    user_id = sqlite3_column_int(stmt, 0);
    expires_at = static_cast<long long>(sqlite3_column_int64(stmt, 1));
    sqlite3_finalize(stmt);
    return true;
  }

  sqlite3_finalize(stmt);
  if (rc == SQLITE_DONE) {
    error_message = "Session not found";
    return false;
  }

  error_message = sqlite3_errmsg(db_);
  return false;
}

bool Database::delete_session(const std::string& token, std::string& error_message) {
  const char* sql = "DELETE FROM sessions WHERE token = ?;";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);

  const int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  return true;
}

bool Database::delete_expired_sessions(std::string& error_message) {
  const char* sql = "DELETE FROM sessions WHERE expires_at < strftime('%s', 'now');";
  return exec_sql(db_, sql, error_message);
}

bool Database::add_note(int user_id, const std::string& content, std::string& error_message) {
  // I always store notes with user_id so later queries can isolate records per user.
  const char* sql = "INSERT INTO notes(user_id, content) VALUES (?, ?);";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_TRANSIENT);

  const int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  return true;
}

bool Database::get_notes_for_user(int user_id,
                                  std::vector<Note>& notes,
                                  std::string& error_message) {
  // I filter by user_id in SQL itself.
  // This is safer than loading all notes and filtering in application code.
  const char* sql =
      "SELECT id, content, created_at FROM notes WHERE user_id = ? ORDER BY id DESC;";

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    error_message = sqlite3_errmsg(db_);
    return false;
  }

  sqlite3_bind_int(stmt, 1, user_id);

  notes.clear();
  while (true) {
    const int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
      Note note{};
      note.id = sqlite3_column_int(stmt, 0);
      const unsigned char* content = sqlite3_column_text(stmt, 1);
      const unsigned char* created = sqlite3_column_text(stmt, 2);
      note.content = content ? reinterpret_cast<const char*>(content) : "";
      note.created_at = created ? reinterpret_cast<const char*>(created) : "";
      notes.push_back(note);
      continue;
    }

    if (rc == SQLITE_DONE) {
      sqlite3_finalize(stmt);
      return true;
    }

    error_message = sqlite3_errmsg(db_);
    sqlite3_finalize(stmt);
    return false;
  }
}
