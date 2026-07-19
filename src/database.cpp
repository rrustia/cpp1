#include "database.hpp"

#include <sqlite3.h>

#include <iostream>

namespace {

bool exec_sql(sqlite3* db, const char* sql, std::string& error_message) {
  // A small helper runs simple SQL statements that do not need bound parameters, like schema creation or cleanup.
  // Input: db is the open SQLite connection, sql is the statement string.
  // Output: Returns true if the statement ran without error. Fills error_message on failure.
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

// Starts with no active SQLite connection.
// Input: No input is required.
// Output: Creates a Database object with db_ set to nullptr.
Database::Database() : db_(nullptr) {}

// Shuts down the owned SQLite connection during object cleanup.
// Input: No input is required.
// Output: Ensures close() runs before the object is destroyed.
Database::~Database() { close(); }

bool Database::open(const std::string& db_path, std::string& error_message) {
  // Opens a persistent SQLite connection that the app keeps open for its entire lifetime.
  // Input: db_path is the file path to the database, error_message is filled on failure.
  // Output: Returns true if the connection opened and foreign keys were enabled successfully.
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
  // Closes the current SQLite connection if one is open.
  // Input: No input is required.
  // Output: The internal database handle is reset to nullptr.
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

bool Database::migrate(std::string& error_message) {
  // Creates the users, sessions, and notes tables if they do not already exist.
  // Safe to call on every startup since every table uses IF NOT EXISTS.
  // Input: error_message is filled with details if any statement fails.
  // Output: Returns true if all tables are ready.
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
  // Inserts a new user record with a prepared statement so no value can be treated as SQL code.
  // Input: username, salt_hex, and password_hash_hex are the credentials to save. error_message is filled on failure.
  // Output: Returns true if the row was inserted successfully.
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
  // Looks up a user by username and returns only the fields needed to verify a login attempt.
  // Input: username is the account name to find. user_id, salt_hex, and password_hash_hex are filled on success. error_message is filled on failure.
  // Output: Returns true if the user was found.
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
  // Saves a session token so the server can validate it on future requests.
  // If a token with the same value already exists, its user and expiry are updated.
  // Input: token is the session string, user_id ties it to an account, expires_at is the Unix expiry timestamp. error_message is filled on failure.
  // Output: Returns true if the session was saved successfully.
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
  // Looks up a session token and returns the associated user id and expiry time.
  // Input: token is the bearer token to find. user_id and expires_at are filled on success. error_message is filled on failure.
  // Output: Returns true if the session was found.
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
  // Removes a specific session from the database, effectively logging that user out.
  // Input: token is the session to remove. error_message is filled on failure.
  // Output: Returns true if the delete ran without error.
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
  // Removes all sessions whose expiry time has already passed, keeping the sessions table clean.
  // Input: error_message is filled on failure.
  // Output: Returns true if the cleanup ran without error.
  const char* sql = "DELETE FROM sessions WHERE expires_at < strftime('%s', 'now');";
  return exec_sql(db_, sql, error_message);
}

bool Database::add_note(int user_id, const std::string& content, std::string& error_message) {
  // Saves a new note and ties it to a specific user so only that user can retrieve it later.
  // Input: user_id is the owner, content is the note text. error_message is filled on failure.
  // Output: Returns true if the note was inserted successfully.
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
  // Fetches all notes for a specific user, ordered newest first.
  // Filtering is done in SQL to avoid loading data that does not belong to the requester.
  // Input: user_id identifies whose notes to fetch. notes is filled with the results. error_message is filled on failure.
  // Output: Returns true if the query ran successfully, even when the user has no notes.
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
