# Only x32
if (NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
	return()
endif()

# Project Name
project(KeyFinder)

# Cpp Standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Current Project
add_library("${PROJECT_NAME}" MODULE "dllmain.cpp")

# Add Library
target_link_libraries("${PROJECT_NAME}" PRIVATE Rut RxHook)