cmake_minimum_required(VERSION 3.9)
project(cpu_info C)

set(CMAKE_C_STANDARD 11)

add_library(${PROJECT_NAME} INTERFACE)
target_sources(${PROJECT_NAME} INTERFACE include/cpu_info.h)
target_include_directories(${PROJECT_NAME} INTERFACE include)

add_subdirectory(examples)