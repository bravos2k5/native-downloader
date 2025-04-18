cmake_minimum_required(VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(downloader)

# Cho phép export DLL symbols
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# C++20
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set(CMAKE_CXX_STANDARD 20)
endif()

# Find OpenSSL via vcpkg (dynamic link, không cần applink.c)
find_package(OpenSSL REQUIRED)

# Build shared library (DLL)
add_library(downloader SHARED downloader.cpp)

# Link OpenSSL
target_include_directories(downloader PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(downloader PRIVATE OpenSSL::SSL OpenSSL::Crypto)



