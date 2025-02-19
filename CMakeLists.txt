project(check_it)
cmake_minimum_required(VERSION 3.10)

if (Windows)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_executable(check_it checkpe.cc main.cc checkelf.cc)

target_include_directories(check_it PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )
