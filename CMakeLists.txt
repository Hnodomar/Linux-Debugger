cmake_minimum_required (VERSION 3.0)
project (Debugger)

add_compile_options(-std=c++14)

file(GLOB SOURCES "src/*.cpp")

include_directories(dependencies/libelfin dependencies/linenoise include)
add_executable(minidbg ${SOURCES} dependencies/linenoise/linenoise.c)

add_executable(hello tests/hello.cpp)
set_target_properties(hello PROPERTIES COMPILE_FLAGS "-g")

add_executable(unwinding tests/stack_unwinding.cpp)
set_target_properties(unwinding PROPERTIES COMPILE_FLAGS "-g")

add_executable(backtrace tests/backtrace.cpp)
set_target_properties(backtrace PROPERTIES COMPILE_FLAGS "-g")

add_custom_target(
	libelfin
	COMMAND make
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/dependencies/libelfin
)
target_link_libraries(minidbg
			${PROJECT_SOURCE_DIR}/dependencies/libelfin/dwarf/libdwarf++.so
			${PROJECT_SOURCE_DIR}/dependencies/libelfin/elf/libelf++.so)
add_dependencies(minidbg libelfin)
