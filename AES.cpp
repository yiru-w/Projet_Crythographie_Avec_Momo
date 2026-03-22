//
// Created by yiru on 20/03/2026.
//

#include "AES.h"

const unsigned char AES::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char AES::Invsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint32_t AES::Rcon[11] = {
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000, //8
    0x10000000, //16
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000
};

AES::AES(const vector<Registre> &key) : w() {
    if (key.size() != Nk) {
        throw invalid_argument("Taille de cles obliger 4");
    }
    this->keyExpansion(key);
}

void AES::chiffrement(Registre state[4]) const {
    Cipher(state);
}

void AES::Dechiffrement(Registre state[4]) const {
    InvCipher(state);
}

void AES::keyExpansion(const vector<Registre> &key) {
    int i = 0;

    while (i < Nk) {
        w[i] = key[i];
        i++;
    }
    i = Nk;
    while (i < Nb*(Nr+1)) {
        Registre temp = w[i-1];
        if (i%Nk == 0) {
            temp.rotationDeByte();
            SubWord(temp);
            temp = temp.XOR(Registre(32, Rcon[i/Nk]));
        }
        w[i] = w[i-Nk].XOR(temp);
        i++;
    }
}

void AES::SubWord(Registre& r) {
    for (int i = 0; i < 4; i++) {
        uint DeuxHexa = r.getByte(i);
        uint nouvelleByte = sbox[DeuxHexa];
        r.setByte(i, nouvelleByte);
    }
}


void AES::InvSubWord(Registre &r) {
    for (int i = 0; i < 4; i++) {
        uint DeuxHexa = r.getByte(i);
        uint nouvelleByte = Invsbox[DeuxHexa];
        r.setByte(i, nouvelleByte);
    }
}

void AES::Cipher(Registre state[4]) const {
    AddRoundKey(state,0);
    for (int i = 1; i < Nr; i++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state,i);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state,Nr);
}

void AES::AddRoundKey(Registre state[4], int indice) const {
    for (int i = 0; i < 4; i++) {
        state[i] = state[i].XOR(w[4*indice+i]);
    }
}

void AES::SubBytes(Registre state[4]) {
    for (int i = 0; i < 4; i++) {
        SubWord(state[i]);
    }
}

void AES::ShiftRows(Registre state[4]) {
    //Premier ligne ne change pas
    //En plus, state c'est placer par colonne
    unsigned char t;
    //Premier ligne ne change pas

    //Deuxieme ligne rotation vers a gauche 1
    //state[0] c'est colone 0 et state[1] c'est colone 1 etc
    //On veut ligne 1 de colone 0 remplacer par ligne 1 de colone 1, ensuite
    //ligne 1 de colone 1 remplacer par ligne 1 de colone 2 etc
    t = state[0].getByte(1);
    state[0].setByte(1, state[1].getByte(1));
    state[1].setByte(1, state[2].getByte(1));
    state[2].setByte(1, state[3].getByte(1));
    state[3].setByte(1, t);

    //Troisieme ligne rotation vers a gauche  2
    //colone 0 change avec colone 2
    t = state[0].getByte(2);
    state[0].setByte(2, state[2].getByte(2));
    state[2].setByte(2, t);
    //colone 1 cahnge avec colone 3
    t = state[1].getByte(2);
    state[1].setByte(2, state[3].getByte(2));
    state[3].setByte(2, t);

    //Quatrieme ligne rotation vers a gauche  3
    t = state[3].getByte(3);
    state[3].setByte(3, state[2].getByte(3));
    state[2].setByte(3, state[1].getByte(3));
    state[1].setByte(3, state[0].getByte(3));
    state[0].setByte(3, t);
}


void AES::MixColumns(Registre state[4]) {
    for (int i= 0; i < 4; i++) {
        Registre s = state[i];
        Registre ApresXtime2 = s.xtime(); // 02 FOIS S
        Registre ApresXtime3 = ApresXtime2.XOR(s);

        //s'0 = ({02} • s0) ⊕ ({03} • s1) ⊕ s2 ⊕ s3
        state[i].setByte(0,ApresXtime2.getByte(0) ^ ApresXtime3.getByte(1) ^ s.getByte(2) ^ s.getByte(3));
        //s'1 = s0 ⊕ ({02} • s1) ⊕ ({03} • s2) ⊕ s3
        state[i].setByte(1,s.getByte(0) ^ ApresXtime2.getByte(1) ^ ApresXtime3.getByte(2) ^ s.getByte(3));
        //s'2 = s0 ⊕ s1 ⊕({02} • s2) ⊕ ({03} • s3)
        state[i].setByte(2,s.getByte(0) ^ s.getByte(1) ^ ApresXtime2.getByte(2) ^ ApresXtime3.getByte(3));
        //s'3 = ({03} • s0) ⊕ s1 ⊕ s2 ⊕ ({02} • s3).
        state[i].setByte(3,ApresXtime3.getByte(0) ^ s.getByte(1) ^ s.getByte(2) ^ ApresXtime2.getByte(3));
    }
}

void AES::InvCipher(Registre state[4]) const {
    AddRoundKey(state,Nr);
    for (int i = Nr -1; i > 0; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state,i);
        InvMixColumns(state);
    }
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state,0);
}

void AES::InvShiftRows(Registre state[4]) {
    // La première ligne (index 0) ne change pas.
    // L'état (state) est organisé par colonnes.
    unsigned char t;
    //Premier ligne ne change pas

    // --- Deuxième ligne (index 1) : Rotation vers la DROITE de 1 ---
    // On déplace chaque octet vers la droite : col 3 -> col 0, col 2 -> col 3, etc.
    t = state[3].getByte(1);
    state[3].setByte(1, state[2].getByte(1));
    state[2].setByte(1, state[1].getByte(1));
    state[1].setByte(1, state[0].getByte(1));
    state[0].setByte(1, t);

    // --- Troisième ligne (index 2) : Rotation vers la DROITE de 2 ---
    // (Équivaut à une rotation vers la gauche de 2, on échange les colonnes opposées)
    // Colonne 0 échange avec colonne 2
    t = state[0].getByte(2);
    state[0].setByte(2, state[2].getByte(2));
    state[2].setByte(2, t);
    // Colonne 1 échange avec colonne 3
    t = state[1].getByte(2);
    state[1].setByte(2, state[3].getByte(2));
    state[3].setByte(2, t);

    // --- Quatrième ligne (index 3) : Rotation vers la DROITE de 3 ---
    // (Équivaut à une rotation vers la GAUCHE de 1)
    // On déplace chaque octet vers la gauche : col 0 -> col 3, col 1 -> col 0, etc.
    t = state[0].getByte(3);
    state[0].setByte(3, state[1].getByte(3));
    state[1].setByte(3, state[2].getByte(3));
    state[2].setByte(3, state[3].getByte(3));
    state[3].setByte(3, t);
}


void AES::InvSubBytes(Registre state[4]) {
    for (int i = 0; i < 4; i++) {
        InvSubWord(state[i]);
    }
}

void AES::InvMixColumns(Registre state[4]) {
    for (int i = 0; i < 4; i++) {
        // 's' représente notre unité de base {01}
        Registre s = state[i];

        // --- ÉTAPE 1 : Générer les puissances de 2 via xtime() ---
        // Le XOR ne peut pas créer de nouvelles puissances (s XOR s = 0).
        // On utilise xtime pour "sauter" aux paliers suivants : 2, 4, 8.
        Registre x2 = s.xtime(); // On obtient {02}
        Registre x4 = x2.xtime(); // On obtient {04} (2 * 2)
        Registre x8 = x4.xtime(); // On obtient {08} (4 * 2)

        // --- ÉTAPE 2 : Assembler les coefficients via XOR ---
        // Une fois qu'on a les briques (8, 4, 2, 1), on peut composer
        // n'importe quel coefficient intermédiaire par simple addition (XOR).
        Registre x9 = x8.XOR(s); // 8 + 1 = 9
        Registre xB = x8.XOR(x2).XOR(s); // 8 + 2 + 1 = 11 = B
        Registre xD = x8.XOR(x4).XOR(s); // 8 + 4 + 1 = 13 = D
        Registre xE = x8.XOR(x4).XOR(x2); // 8 + 4 + 2 = 14 = E

        state[i].setByte(0, xE.getByte(0) ^ xB.getByte(1) ^ xD.getByte(2) ^ x9.getByte(3));
        state[i].setByte(1, x9.getByte(0) ^ xE.getByte(1) ^ xB.getByte(2) ^ xD.getByte(3));
        state[i].setByte(2, xD.getByte(0) ^ x9.getByte(1) ^ xE.getByte(2) ^ xB.getByte(3));
        state[i].setByte(3, xB.getByte(0) ^ xD.getByte(1) ^ x9.getByte(2) ^ xE.getByte(3));
    }
}

vector<unsigned char> AES::ChiffrementECB(const vector<unsigned char> &TextNonChiffremnt) {
    vector<unsigned char> TextChiffrement;
    // On divise le message en blocs de 128 bits (16 octets)
    for (int i = 0; i < TextNonChiffremnt.size(); i+=16) {
        // Initialisation de la matrice d'état (4 colonnes de 32 bits)
        Registre state[4] = {Registre(32), Registre(32), Registre(32), Registre(32)};
        //On remplace dabord colone 0 de tt ligne, ensuite colone 1 de tt ligne ...
        for (int colone = 0;  colone< 4; colone++) {
            for (int ligne = 0; ligne < 4; ligne++) {
                //Index c'est parce que dans ordin n'a pas matrice
                //Donc on a passer les colonnes qu'on a deja fait
                uint index = i + (colone * 4) + ligne;
                uint8_t byte;
                if (index < TextNonChiffremnt.size()) {
                    byte = TextNonChiffremnt[index];
                } else {
                    byte = 0;
                }
                state[colone].setByte(ligne, byte);
            }
        }
        this->Cipher(state);
        for (int colone = 0; colone < 4; colone++) {
            for (int ligne = 0; ligne < 4; ligne++) {
                TextChiffrement.push_back(state[colone].getByte(ligne));
            }
        }
    }
    return TextChiffrement;
}


vector<unsigned char> AES::DechiffrementECB(const vector<unsigned char> &TextChirrement) {
    vector<unsigned char> TextDeChiffrement;
    // On divise le message en blocs de 128 bits (16 octets)
    for (int i = 0; i < TextChirrement.size(); i+=16) {
        // Initialisation de la matrice d'état (4 colonnes de 32 bits)
        Registre state[4] = {Registre(32), Registre(32), Registre(32), Registre(32)};
        //On remplace dabord colone 0 de tt ligne, ensuite colone 1 de tt ligne ...
        for (int colone = 0;  colone< 4; colone++) {
            for (int ligne = 0; ligne < 4; ligne++) {
                //Index c'est parce que dans ordin n'a pas matrice
                //Donc on a passer les colonnes qu'on a deja fait
                uint index = i + (colone * 4) + ligne;
                uint8_t byte;
                if (index < TextChirrement.size()) {
                    byte = TextChirrement[index];
                } else {
                    byte = 0;
                }
                state[colone].setByte(ligne, byte);
            }
        }
        this->InvCipher(state);
        for (int colone = 0; colone < 4; colone++) {
            for (int ligne = 0; ligne < 4; ligne++) {
                TextDeChiffrement.push_back(state[colone].getByte(ligne));
            }
        }
    }
    return TextDeChiffrement;
}
