cmake_minimum_required(VERSION 3.20)
project(VaultCore VERSION 0.1.0 LANGUAGES CXX)

option(VAULTCORE_BUILD_TESTS "Build VaultCore test suite" ON)
option(VAULTCORE_ENABLE_SANITIZERS "Enable ASan/UBSan for Clang/GCC" OFF)

add_library(vaultcore_lib STATIC
    src/hash.cpp
    src/vault.cpp
)
add_library(vaultcore::lib ALIAS vaultcore_lib)
target_compile_features(vaultcore_lib PUBLIC cxx_std_20)
target_include_directories(vaultcore_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
if(MSVC)
    target_compile_options(vaultcore_lib PRIVATE /W4 /permissive-)
else()
    target_compile_options(vaultcore_lib PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()
if(VAULTCORE_ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(vaultcore_lib PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(vaultcore_lib PUBLIC -fsanitize=address,undefined)
endif()

add_executable(vaultcore src/main.cpp)
target_link_libraries(vaultcore PRIVATE vaultcore::lib)

include(CTest)
if(BUILD_TESTING AND VAULTCORE_BUILD_TESTS)
    add_executable(vaultcore_tests tests/test_vault.cpp)
    target_link_libraries(vaultcore_tests PRIVATE vaultcore::lib)
    add_test(NAME vaultcore_tests COMMAND vaultcore_tests)
endif()

install(TARGETS vaultcore RUNTIME DESTINATION bin)
