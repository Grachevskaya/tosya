# uidbench: the timing instrument for the module's hot path, cross compiled for the device.
# It ships with nothing: it is run by hand, on a device, before and after a change.
cmake_minimum_required(VERSION 3.22)
project(uidbench C)
set(CMAKE_C_STANDARD 11)
add_executable(uidbench uidbench.c)
