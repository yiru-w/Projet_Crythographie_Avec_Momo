cmake_minimum_required(VERSION 4.1)
project(untitled)

set(CMAKE_CXX_STANDARD 20)

add_executable(TP1-Crypthographie main.cpp
        LFSR.cpp
        LFSR.h
        Registre.cpp
        Registre.h
        AES.cpp
        AES.h)
