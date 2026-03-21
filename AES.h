//
// Created by yiru on 20/03/2026.
//

#ifndef UNTITLED_AES_H
#define UNTITLED_AES_H

#include <cstdint>
#include <vector>

#include "Registre.h"

using namespace std;

class AES {
    static const int Nb = 4;
    static const int Nk = 4;
    static const int Nr = 10;
    static const unsigned char sbox[256];
    static const uint32_t Rcon[11];

    Registre w[Nb * (Nr + 1)];

    //Generer cles
    void keyExpansion(const vector<Registre> &Key);
    static void SubWord(Registre& r);

    //Chiffrement
    void Cipher(Registre state[4]);
    void AddRoundKey(Registre state[4], int indice) const;
    static void SubBytes(Registre state[4]);
    void ShiftRows(Registre state[4]);
    void MixColumns(Registre state[4]);

};


#endif //UNTITLED_AES_H