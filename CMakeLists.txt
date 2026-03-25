cmake_minimum_required(VERSION 3.10)
project(Projet_Crythographie_Avec_Momo)

set(CMAKE_CXX_STANDARD 20)

add_executable(Projet_Crythographie_Avec_Momo main.cpp
        Registre.cpp
        Registre.h
        AES.cpp
        AES.h
)

