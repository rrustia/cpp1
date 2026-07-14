cmake_minimum_required(VERSION 3.20)
project(private_data_app LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# I use FetchContent so this project can build without manually downloading headers.
FetchContent_Declare(
  cpp_httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.17.3
)

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(cpp_httplib nlohmann_json)

find_package(SQLite3 REQUIRED)

add_executable(private_data_app
  src/main.cpp
  src/database.cpp
  src/auth.cpp
)

target_include_directories(private_data_app PRIVATE src)

target_link_libraries(private_data_app
  PRIVATE
    SQLite3::SQLite3
    httplib::httplib
    nlohmann_json::nlohmann_json
)

if(APPLE)
  # I link Security because I rely on CommonCrypto for SHA256 hashing on macOS.
  target_link_libraries(private_data_app PRIVATE "-framework Security")
endif()
