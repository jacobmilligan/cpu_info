# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/Jacob/Dev/Repos/cpu_info

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/Jacob/Dev/Repos/cpu_info/bin

# Include any dependencies generated for this target.
include examples/CMakeFiles/basic_example.dir/depend.make

# Include the progress variables for this target.
include examples/CMakeFiles/basic_example.dir/progress.make

# Include the compile flags for this target's objects.
include examples/CMakeFiles/basic_example.dir/flags.make

examples/CMakeFiles/basic_example.dir/basic.c.o: examples/CMakeFiles/basic_example.dir/flags.make
examples/CMakeFiles/basic_example.dir/basic.c.o: ../examples/basic.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/Jacob/Dev/Repos/cpu_info/bin/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object examples/CMakeFiles/basic_example.dir/basic.c.o"
	cd /Users/Jacob/Dev/Repos/cpu_info/bin/examples && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/basic_example.dir/basic.c.o   -c /Users/Jacob/Dev/Repos/cpu_info/examples/basic.c

examples/CMakeFiles/basic_example.dir/basic.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/basic_example.dir/basic.c.i"
	cd /Users/Jacob/Dev/Repos/cpu_info/bin/examples && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/Jacob/Dev/Repos/cpu_info/examples/basic.c > CMakeFiles/basic_example.dir/basic.c.i

examples/CMakeFiles/basic_example.dir/basic.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/basic_example.dir/basic.c.s"
	cd /Users/Jacob/Dev/Repos/cpu_info/bin/examples && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/Jacob/Dev/Repos/cpu_info/examples/basic.c -o CMakeFiles/basic_example.dir/basic.c.s

examples/CMakeFiles/basic_example.dir/basic.c.o.requires:

.PHONY : examples/CMakeFiles/basic_example.dir/basic.c.o.requires

examples/CMakeFiles/basic_example.dir/basic.c.o.provides: examples/CMakeFiles/basic_example.dir/basic.c.o.requires
	$(MAKE) -f examples/CMakeFiles/basic_example.dir/build.make examples/CMakeFiles/basic_example.dir/basic.c.o.provides.build
.PHONY : examples/CMakeFiles/basic_example.dir/basic.c.o.provides

examples/CMakeFiles/basic_example.dir/basic.c.o.provides.build: examples/CMakeFiles/basic_example.dir/basic.c.o


# Object files for target basic_example
basic_example_OBJECTS = \
"CMakeFiles/basic_example.dir/basic.c.o"

# External object files for target basic_example
basic_example_EXTERNAL_OBJECTS =

examples/basic_example: examples/CMakeFiles/basic_example.dir/basic.c.o
examples/basic_example: examples/CMakeFiles/basic_example.dir/build.make
examples/basic_example: examples/CMakeFiles/basic_example.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/Jacob/Dev/Repos/cpu_info/bin/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable basic_example"
	cd /Users/Jacob/Dev/Repos/cpu_info/bin/examples && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/basic_example.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
examples/CMakeFiles/basic_example.dir/build: examples/basic_example

.PHONY : examples/CMakeFiles/basic_example.dir/build

examples/CMakeFiles/basic_example.dir/requires: examples/CMakeFiles/basic_example.dir/basic.c.o.requires

.PHONY : examples/CMakeFiles/basic_example.dir/requires

examples/CMakeFiles/basic_example.dir/clean:
	cd /Users/Jacob/Dev/Repos/cpu_info/bin/examples && $(CMAKE_COMMAND) -P CMakeFiles/basic_example.dir/cmake_clean.cmake
.PHONY : examples/CMakeFiles/basic_example.dir/clean

examples/CMakeFiles/basic_example.dir/depend:
	cd /Users/Jacob/Dev/Repos/cpu_info/bin && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/Jacob/Dev/Repos/cpu_info /Users/Jacob/Dev/Repos/cpu_info/examples /Users/Jacob/Dev/Repos/cpu_info/bin /Users/Jacob/Dev/Repos/cpu_info/bin/examples /Users/Jacob/Dev/Repos/cpu_info/bin/examples/CMakeFiles/basic_example.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/CMakeFiles/basic_example.dir/depend

