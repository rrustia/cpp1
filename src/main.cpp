#include <httplib.h>
#include <nlohmann/json.hpp>

#include <iostream>

#include "auth.hpp"
#include "database.hpp"

using json = nlohmann::json;

namespace {

void json_response(httplib::Response& res, int status, const json& payload) {
  // Sends a JSON response with the given HTTP status code and body.
  // All routes use this helper so the frontend always receives the same format.
  // Pretty printing is used to make responses easier to read during development.
  // Input: res is the response object to populate, status is the HTTP status code, payload is the JSON to send.
  // Output: The response object is updated in place with the content type and formatted body.
  res.status = status;
  res.set_content(payload.dump(2), "application/json");
}

bool parse_json_body(const httplib::Request& req, json& body, std::string& error_message) {
  try {
    // Parses the request body as JSON so each route does not have to handle parsing on its own.
    // Input: req is the incoming request, body is filled with the parsed result. error_message is filled on failure.
    // Output: Returns true if the body was valid JSON.
    body = json::parse(req.body);
    if (!body.is_object()) {
      error_message = "JSON body must be an object";
      return false;
    }
    return true;
  } catch (const std::exception& ex) {
    error_message = std::string("Invalid JSON: ") + ex.what();
    return false;
  }
}

std::string read_bearer_token(const httplib::Request& req) {
  // Extracts the bearer token value from the Authorization header of an incoming request.
  // If the header is absent or does not follow the Bearer format, an empty string is returned.
  // Input: req is the incoming HTTP request.
  // Output: Returns the token string, or an empty string if no valid bearer token was present.
  const auto auth_header = req.get_header_value("Authorization");
  const std::string prefix = "Bearer ";
  if (auth_header.rfind(prefix, 0) == 0) {
    return auth_header.substr(prefix.size());
  }
  return "";
}

}  // namespace

int main() {
  // Starts the application by preparing the database, wiring the routes, and launching the HTTP server.
  // Input: No command line input is used.
  // Output: Returns 0 on a clean shutdown, or 1 if startup fails.
  Database db;
  std::string error;

  // Opens and migrates the database before anything else so the server never starts with a missing or outdated schema.
  if (!db.open("app.db", error)) {
    std::cerr << "Failed to open database: " << error << "\n";
    return 1;
  }
  if (!db.migrate(error)) {
    std::cerr << "Failed to migrate database: " << error << "\n";
    return 1;
  }

  AuthService auth;
  httplib::Server server;

  server.set_mount_point("/", "./web");

  server.Post("/api/register", [&](const httplib::Request& req, httplib::Response& res) {
    // Handles new account creation by reading username and password from the request body and passing them to the auth service.
    // Input: JSON body with "username" and "password" fields.
    // Output: 201 with a success message, or 400 with an error message.
    json body;
    std::string parse_error;
    if (!parse_json_body(req, body, parse_error)) {
      json_response(res, 400, {{"error", parse_error}});
      return;
    }

    const std::string username = body.value("username", "");
    const std::string password = body.value("password", "");

    std::string register_error;
    if (!auth.register_user(db, username, password, register_error)) {
      json_response(res, 400, {{"error", register_error}});
      return;
    }

    json_response(res, 201, {{"message", "User created"}});
  });

  server.Post("/api/login", [&](const httplib::Request& req, httplib::Response& res) {
    // Handles login by verifying credentials and returning a session token the client uses for future requests.
    // Input: JSON body with "username" and "password" fields.
    // Output: 200 with a token on success, or 401 with an error message.
    json body;
    std::string parse_error;
    if (!parse_json_body(req, body, parse_error)) {
      json_response(res, 400, {{"error", parse_error}});
      return;
    }

    const std::string username = body.value("username", "");
    const std::string password = body.value("password", "");

    std::string token;
    std::string login_error;
    if (!auth.login(db, username, password, token, login_error)) {
      json_response(res, 401, {{"error", login_error}});
      return;
    }

    json_response(res, 200, {{"token", token}});
  });

  server.Post("/api/logout", [&](const httplib::Request& req, httplib::Response& res) {
    // Logs the current user out by removing the session linked to the bearer token.
    // Input: Authorization header with a bearer token.
    // Output: 200 with a confirmation message, or 401 or 500 on failure.
    const std::string token = read_bearer_token(req);
    if (token.empty()) {
      json_response(res, 401, {{"error", "Missing bearer token"}});
      return;
    }

    std::string logout_error;
    if (!db.delete_session(token, logout_error)) {
      json_response(res, 500, {{"error", logout_error}});
      return;
    }

    json_response(res, 200, {{"message", "Logged out"}});
  });

  server.Get("/api/me/notes", [&](const httplib::Request& req, httplib::Response& res) {
    // Returns all notes belonging to the authenticated user.
    // The token is verified first, then notes are fetched using only that user's id so no other user's data can come through.
    // Input: Authorization header with a valid bearer token.
    // Output: 200 with a notes array, or 401 if the token is invalid.
    const std::string token = read_bearer_token(req);

    int user_id = 0;
    std::string auth_error;
    if (!auth.authenticate_token(db, token, user_id, auth_error)) {
      json_response(res, 401, {{"error", auth_error}});
      return;
    }

    std::vector<Note> notes;
    std::string db_error;
    if (!db.get_notes_for_user(user_id, notes, db_error)) {
      json_response(res, 500, {{"error", db_error}});
      return;
    }

    json list = json::array();
    for (const auto& note : notes) {
      list.push_back({
          {"id", note.id},
          {"content", note.content},
          {"created_at", note.created_at},
      });
    }

    json_response(res, 200, {{"notes", list}});
  });

  server.Post("/api/me/notes", [&](const httplib::Request& req, httplib::Response& res) {
    // Saves a new note for the authenticated user.
    // The same token check used for reading notes is applied here so the access rules stay consistent.
    // Input: Authorization header with a valid bearer token, and a JSON body with a "content" field.
    // Output: 201 with a success message, or 400 or 401 on failure.
    const std::string token = read_bearer_token(req);

    int user_id = 0;
    std::string auth_error;
    if (!auth.authenticate_token(db, token, user_id, auth_error)) {
      json_response(res, 401, {{"error", auth_error}});
      return;
    }

    json body;
    std::string parse_error;
    if (!parse_json_body(req, body, parse_error)) {
      json_response(res, 400, {{"error", parse_error}});
      return;
    }

    const std::string content = body.value("content", "");
    if (content.empty()) {
      json_response(res, 400, {{"error", "content is required"}});
      return;
    }

    std::string db_error;
    if (!db.add_note(user_id, content, db_error)) {
      json_response(res, 500, {{"error", db_error}});
      return;
    }

    json_response(res, 201, {{"message", "Note added"}});
  });

  server.Get("/api/health", [&](const httplib::Request&, httplib::Response& res) {
    // A minimal endpoint that confirms the server is running and able to respond.
    // Input: No body or headers required.
    // Output: 200 with a status field set to "ok".
    json_response(res, 200, {{"status", "ok"}});
  });

  std::cout << "Server listening on http://127.0.0.1:8080\n";
  if (!server.listen("127.0.0.1", 8080)) {
    std::cerr << "Failed to start server\n";
    return 1;
  }

  return 0;
}
