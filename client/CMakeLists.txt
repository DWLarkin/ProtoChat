cmake_minimum_required(VERSION 3.20)

project(
    client
    VERSION 0.1.0
    LANGUAGES C
)

add_executable(
    ${PROJECT_NAME}
    "src/main.c"
    "src/protochat.c"
)

target_include_directories(${PROJECT_NAME} PRIVATE include)

target_compile_features(${PROJECT_NAME} PRIVATE c_std_11)
