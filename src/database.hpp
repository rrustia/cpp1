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
  // Sets up an empty database wrapper before a connection is opened.
  // Input: No input is required.
  // Output: Creates a Database object with a null SQLite handle.
  Database();

  // Releases the database connection when the wrapper goes out of scope.
  // Input: No input is required.
  // Output: Closes any open SQLite handle owned by this object.
  ~Database();

  // Opens the SQLite database file at the given path and enables foreign key enforcement.
  // Input: db_path is the file path, error_message is filled on failure.
  // Output: Returns true if the connection was opened successfully.
  bool open(const std::string& db_path, std::string& error_message);

  // Closes the database connection and releases its resources.
  // Input: No input is required.
  // Output: Any open SQLite handle is closed and cleared.
  void close();

  // Creates the required tables if they do not already exist.
  // Input: error_message is filled on failure.
  // Output: Returns true if all tables are ready.
  bool migrate(std::string& error_message);

  // Inserts a new user record into the database.
  // Input: username, salt_hex, and password_hash_hex are the credentials to store. error_message is filled on failure.
  // Output: Returns true if the user was inserted successfully.
  bool create_user(const std::string& username,
                   const std::string& salt_hex,
                   const std::string& password_hash_hex,
                   std::string& error_message);

  // Looks up a user by username and returns the data needed to verify a login attempt.
  // Input: username is the account to find. user_id, salt_hex, and password_hash_hex are filled on success. error_message is filled on failure.
  // Output: Returns true if the user was found.
  bool get_user_auth_data(const std::string& username,
                          int& user_id,
                          std::string& salt_hex,
                          std::string& password_hash_hex,
                          std::string& error_message);

  // Saves a session token so future requests can be authenticated without re-entering a password.
  // Input: token is the session string, user_id ties it to an account, expires_at is the Unix expiry timestamp. error_message is filled on failure.
  // Output: Returns true if the session was saved successfully.
  bool save_session(const std::string& token,
                    int user_id,
                    long long expires_at,
                    std::string& error_message);

  // Looks up a session token and returns the associated user id and expiry time.
  // Input: token is the bearer token to find. user_id and expires_at are filled on success. error_message is filled on failure.
  // Output: Returns true if the session was found.
  bool get_session(const std::string& token,
                   int& user_id,
                   long long& expires_at,
                   std::string& error_message);

  // Removes a specific session from the database, effectively logging that user out.
  // Input: token is the session to remove. error_message is filled on failure.
  // Output: Returns true if the delete ran without error.
  bool delete_session(const std::string& token, std::string& error_message);

  // Removes all sessions whose expiry time has already passed, keeping the table clean.
  // Input: error_message is filled on failure.
  // Output: Returns true if the cleanup ran without error.
  bool delete_expired_sessions(std::string& error_message);

  // Saves a new note and ties it to a specific user so only that user can retrieve it.
  // Input: user_id is the owner, content is the note text. error_message is filled on failure.
  // Output: Returns true if the note was inserted successfully.
  bool add_note(int user_id, const std::string& content, std::string& error_message);

  // Fetches all notes belonging to a specific user, ordered newest first.
  // Input: user_id identifies the owner, notes is filled with the results. error_message is filled on failure.
  // Output: Returns true if the query ran successfully, even when the user has no notes.
  bool get_notes_for_user(int user_id, std::vector<Note>& notes, std::string& error_message);

 private:
  sqlite3* db_;
};
