# target a cmake version, you can target a lower version if you like
cmake_minimum_required(VERSION 3.20)

# declare our stub
project(stub CXX)

# this line will mark our stub as MultiThreaded, instead of MultiThreadedDLL
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# this will collect header and source files into a convenient variable
file(GLOB_RECURSE SRC_FILES FOLLOW_SYMLINKS ${PROJECT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE HEADER_FILES FOLLOW_SYMLINKS ${PROJECT_SOURCE_DIR}/src/*.hpp)

# this will give you source groups in the resulting Visual Studio project
source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Header Files" FILES ${HEADER_FILES})
source_group(TREE "${PROJECT_SOURCE_DIR}" PREFIX "Source Files" FILES ${SRC_FILES})


add_subdirectory(${PROJECT_SOURCE_DIR}/zlib-1.3)

# this will create our stub executable
add_executable(stub ${HEADER_FILES} ${SRC_FILES})
add_executable(dummy_executable test.c)

# this will link the parent zlib project to our stub
target_link_libraries(stub zlibstatic)


find_package(OpenSSL REQUIRED)
target_link_libraries(stub OpenSSL::SSL)

target_include_directories(stub PUBLIC
  "${PROJECT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>"
  "${PROJECT_SOURCE_DIR}/zlib-1.3"
  "${CMAKE_CURRENT_BINARY_DIR}/zlib-1.3"
)

enable_testing()
add_test(NAME test_pack
  COMMAND python "${PROJECT_SOURCE_DIR}/packer_executable/main.py" "${PROJECT_BINARY_DIR}/Debug/dummy_executable.exe" -p "${PROJECT_BINARY_DIR}/Debug/stub.exe")


add_test(NAME test_packed
  COMMAND "${PROJECT_BINARY_DIR}/packed.exe")