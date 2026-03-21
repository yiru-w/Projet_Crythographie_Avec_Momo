
#include "Registre.h"
#include <iomanip>
#include <complex>
#include <cstdint>

/**
 * On définit 2 masque, l'un avec que des 1 et l'autre avec que des 0. Ca pourrait
 * être utile...
 */
#define MASK1 0b1111111111111111111111111111111111111111111111111111111111111111
#define MASK0 0b0

Registre::Registre(uint t) : taille(t) {}

Registre::Registre(uint t, const string& strVal) : taille(t) {
    setValeur(strVal);
}
Registre::Registre(uint t, uint32_t val) : taille(t), registre(val) {}

uint Registre::getTaille() const {
    return taille;
}

uint Registre::get(uint numbit) const {
    if (numbit>=taille)
        throw invalid_argument("Indice incorrect");
    return registre>>(taille-1-numbit)&1;
}

unsigned char Registre::getByte(uint numbit) const {
    if (taille != 32) {
        throw invalid_argument("Registre doit etre de 32 bits (4 octets)");
    }
    if (numbit > 3) {
        throw invalid_argument("L'indice du byte doit etre entre 0 et 3");
    }
    return registre >> (8*(3-numbit)) & 0xFF;
}


void Registre::setByte(uint numbit, unsigned char b) {
    if (taille != 32) {
        throw invalid_argument("Registre doit etre de 32 bits (4 octets)");
    }
    if (numbit > 3) {
        throw invalid_argument("L'indice du byte doit etre entre 0 et 3");
    }
    uint shift = 8 * (3 - numbit);
    ullong reg = 0xFFULL << shift;
    registre &= ~reg;
    registre |= (static_cast<ullong>(b) << shift);

}

void Registre::set(uint numbit, uint b) {

    if (numbit>=taille) {
        throw invalid_argument("Indice incorrect");
    }
    if (b != 0 && b != 1) {
        throw invalid_argument("b doit etre 0 ou 1");
    }
    ullong reg = 1ULL << (taille-1-numbit);
    if (b == 1) {
        registre |= reg;
    }
    else {
        registre &= ~reg;
    }
}

Registre Registre::xtime() const {
    // m(x) = x^8 + x^4 + x^3 + x + 1 = 1 0001 1011 (9 bits)
    // Comme on travaille sur 8 bits (un octet), on ignore le bit de poids fort (x^8)
    // et on utilise 0001 1011 = 0x1B pour la réduction.
    //
    // Quand on décale vers la gauche (multiplication par {02}),
    // si le bit le plus à gauche était 1, le résultat dépasse 8 bits (débordement).
    // On fait alors un XOR avec 0x1B pour ramener le résultat dans GF(2^8).
    //
    // Exemple : 1011 0111 (0xB7)
    // Décalage : 1 0110 1110  <-- Le '1' de gauche est en trop
    // XOR m(x) : 1 0001 1011  <-- Le '1' de m(x) annule le '1' en trop
    // Résultat : 0 0111 0101 (0x75)
    Registre r(32);
    for (int i = 0; i < 4; i++) {
        unsigned char b = this->getByte(i);
        if (this->get(i * 8) == 1) {
            b = (b << 1) ^ 0x1b;
        }else {
            b = b << 1;
        }
        r.setByte(i, b);
    }
    return r;
}

void Registre::rotationDeByte() {
    if (taille != 32) {
        throw invalid_argument("Registre doit etre de 32 bits (4 octets)");
    }
    ullong byteAgauche = (registre >> 24) & 0xFF;
    registre <<= 8;
    registre &= 0xFFFFFFFF;
    registre |= byteAgauche ;
}

void Registre::shiftL(uint nbbits) {
    registre <<= nbbits;
    //Exemple : 1001 -> 10010.
    //reg = 10000 - 1 = 01111
    //10010 & 01111 = 00010
    const ullong reg = (1ULL << taille) - 1;
    registre &= reg;
}

void Registre::setValeur(const string& strVal) {
    if (strVal.length() != taille)
        throw invalid_argument("Longueur de la chaine d'initialisation incorrecte");
    registre = 0;
    for (uint i = 0; i < taille; i++) {
        if (strVal[i] == '1') {
            registre |= (1ULL << (taille - 1 - i));
        }
    }
}

string Registre::toBin() const {
    string str;
    for (int i = 0; i < taille; ++i) {
        str += (this->get(i) == 0 ? "0" : "1");
    }
    return str;
}

string Registre::toHex() const {
    stringstream ss;
    ss << hex << uppercase << setw(static_cast<int>(taille / 4)) << setfill('0') << registre;
    return ss.str();
}


bool Registre::operator==(const Registre & r) const {
    return (registre == r.registre && taille == r.taille);
}

ostream& operator<<(ostream& f, const Registre& r) {
    f << r.toBin();
    return f;
}

const Registre& Registre::operator=(const Registre &r) {
    if (&r == this)
        return r;

    this->taille = r.taille;
    this->registre = r.registre;

    return *this;
}
Registre Registre::XOR(const Registre& r) const {
    if (taille != r.taille)
        throw invalid_argument("XOR entre 2 registres de tailles différentes");

    Registre registre_res(taille);

    registre_res.registre = registre ^ r.registre;

    return registre_res;
}