#include <httplib.h>
#include <nlohmann/json.hpp>

#include <iostream>

#include "auth.hpp"
#include "database.hpp"

using json = nlohmann::json;

namespace {

void json_response(httplib::Response& res, int status, const json& payload) {
  // I return all API replies as JSON so the frontend has one predictable format to read.
  // I also pretty print with indentation because this is a learning project and easier to inspect.
  res.status = status;
  res.set_content(payload.dump(2), "application/json");
}

bool parse_json_body(const httplib::Request& req, json& body, std::string& error_message) {
  try {
    // I parse the request body here once per route to keep route logic short and readable.
    body = json::parse(req.body);
    return true;
  } catch (const std::exception& ex) {
    error_message = std::string("Invalid JSON: ") + ex.what();
    return false;
  }
}

std::string read_bearer_token(const httplib::Request& req) {
  // I expect clients to send a header like Authorization: Bearer <token>.
  // If the prefix does not match, I return an empty string and the route can reject the request.
  const auto auth_header = req.get_header_value("Authorization");
  const std::string prefix = "Bearer ";
  if (auth_header.rfind(prefix, 0) == 0) {
    return auth_header.substr(prefix.size());
  }
  return "";
}

}  // namespace

int main() {
  Database db;
  std::string error;

  // I open and migrate the database first so the server never starts in a broken state.
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
    // I keep registration explicit so beginners can trace every step from request to database write.
    json body;
    if (!parse_json_body(req, body, error)) {
      json_response(res, 400, {{"error", error}});
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
    // I issue a session token after login instead of reusing passwords in future requests.
    json body;
    if (!parse_json_body(req, body, error)) {
      json_response(res, 400, {{"error", error}});
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
    // I authenticate first, then query by user id.
    // This is the key rule that keeps each user limited to only their own data.
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
    // I reuse the same token check for write operations so read and write stay consistent.
    const std::string token = read_bearer_token(req);

    int user_id = 0;
    std::string auth_error;
    if (!auth.authenticate_token(db, token, user_id, auth_error)) {
      json_response(res, 401, {{"error", auth_error}});
      return;
    }

    json body;
    if (!parse_json_body(req, body, error)) {
      json_response(res, 400, {{"error", error}});
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
    // I keep this endpoint tiny because it is useful for automated health checks.
    json_response(res, 200, {{"status", "ok"}});
  });

  std::cout << "Server listening on http://127.0.0.1:8080\n";
  if (!server.listen("127.0.0.1", 8080)) {
    std::cerr << "Failed to start server\n";
    return 1;
  }

  return 0;
}
