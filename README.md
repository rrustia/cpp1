# Private Notes Web App with C plus plus Backend

<!-- Purpose: This document explains the private notes application and works as a simple reference for building, running, and understanding the project. -->
<!-- Input: A reader uses a macOS machine, a terminal, and the listed build tools. -->
<!-- Output: By the end, a reader can build the server, start the app, register an account, save notes, and understand the main API flow. -->

The project shows a full stack application with a C plus plus backend API, SQLite storage, and a small HTML CSS JavaScript frontend.

## Technologies used

- C plus plus 17 for backend application logic
- cpp-httplib for HTTP server and API routing
- nlohmann json for JSON parsing and response formatting
- SQLite3 for persistent data storage
- CommonCrypto SHA256 for password hashing on macOS
- HTML, CSS, and vanilla JavaScript for the web interface
- CMake for cross platform build configuration

The app supports:
- User registration
- User login with secure password hashing
- Session token authentication
- Saving private notes for each user
- Retrieving only the notes that belong to the logged in user

## Why this project is useful

The project demonstrates a practical multi user system where private data stays protected behind authentication.

The interface stays simple and beginner friendly while still showing important backend security ideas:
- Salted password hashing with many SHA256 rounds
- Constant time hash comparison
- Random session tokens
- Token expiration
- SQL prepared statements to prevent SQL injection

## Project structure

- `CMakeLists.txt` build configuration
- `src/main.cpp` HTTP server and API routes
- `src/database.hpp` database interface
- `src/database.cpp` SQLite implementation
- `src/auth.hpp` authentication interface
- `src/auth.cpp` authentication and password hashing logic
- `web/index.html` frontend page
- `web/styles.css` frontend styles
- `web/app.js` frontend behavior
- `.gitignore` ignored files

## Requirements

On macOS:
- CMake 3.20 or newer
- A C plus plus compiler with C plus plus 17 support
- SQLite development library
- Internet access for first build to download header dependencies

A reader can install build tools with Homebrew if needed:

```bash
brew install cmake
```

## Build and run

From the project root:

```bash
cmake -S . -B build
cmake --build build
./build/private_data_app
```

When the server starts, it listens at:
- http://127.0.0.1:8080

A browser can then open:
- http://127.0.0.1:8080

## Beginner walkthrough

1. Register a user
- Enter a username like `alice_01`
- Enter a password with at least 8 characters
- Click Register

2. Login
- Use the same username and password
- Click Login
- The app stores the session token in browser memory

3. Add private notes
- Write a note
- Click Save Note
- Click Refresh Notes to fetch notes from the database

4. Logout
- Click Logout
- The token can no longer access note endpoints after logout

## API reference

### Health check

- Method: `GET`
- Path: `/api/health`
- Success response:

```json
{
  "status": "ok"
}
```

### Register

- Method: `POST`
- Path: `/api/register`
- Request body:

```json
{
  "username": "alice_01",
  "password": "secret123"
}
```

- Success response status: `201`

### Login

- Method: `POST`
- Path: `/api/login`
- Request body:

```json
{
  "username": "alice_01",
  "password": "secret123"
}
```

- Success response status: `200`
- Success response body includes token:

```json
{
  "token": "long_random_token"
}
```

### Add note

- Method: `POST`
- Path: `/api/me/notes`
- Header: `Authorization: Bearer <token>`
- Request body:

```json
{
  "content": "A private note"
}
```

- Success response status: `201`

### Get notes for the current user

- Method: `GET`
- Path: `/api/me/notes`
- Header: `Authorization: Bearer <token>`

- Success response status: `200`
- Response example:

```json
{
  "notes": [
    {
      "id": 1,
      "content": "A private note",
      "created_at": "2026-07-14 12:00:00"
    }
  ]
}
```

### Logout

- Method: `POST`
- Path: `/api/logout`
- Header: `Authorization: Bearer <token>`

- Success response status: `200`

## Manual curl testing

Run the server in one terminal, then use another terminal for the requests below:

Register:

```bash
curl -s -X POST http://127.0.0.1:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice_01","password":"secret123"}'
```

Login:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice_01","password":"secret123"}' | jq -r .token)

echo "$TOKEN"
```

Add note:

```bash
curl -s -X POST http://127.0.0.1:8080/api/me/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"content":"hello from alice"}'
```

Read notes:

```bash
curl -s http://127.0.0.1:8080/api/me/notes \
  -H "Authorization: Bearer $TOKEN"
```

Logout:

```bash
curl -s -X POST http://127.0.0.1:8080/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

## Notes for beginners

- Data is stored in `app.db` in the project root.
- A clean database can be created by stopping the server and deleting `app.db`.
- The project stays intentionally small so a reader can inspect every file.
- A production version should add HTTPS, CSRF protection, a stronger password policy, and a refresh token strategy.
