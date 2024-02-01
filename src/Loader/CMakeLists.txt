# Project Name
project(Loader)

# Cpp Standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Current Project
add_executable("${PROJECT_NAME}" "main.cpp")

# Add Library
target_link_libraries("${PROJECT_NAME}" PRIVATE Rut RxHook)