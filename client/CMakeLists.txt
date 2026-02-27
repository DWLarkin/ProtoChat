cmake_minimum_required(VERSION 3.20)

project(
    client
    VERSION 1.0.0
    LANGUAGES C
)

add_executable(
    ${PROJECT_NAME}
    "src/main.c"
    "src/protoclient.c"
    "src/setup.c"
    "src/input_output.c"
    "src/networking.c"
)

target_include_directories(${PROJECT_NAME} PRIVATE include)

target_compile_features(${PROJECT_NAME} PRIVATE c_std_11)
