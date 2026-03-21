

#ifndef LFSR_REGISTRE_H
#define LFSR_REGISTRE_H

#include <iostream>
#include <string>
#include <bits/stdint-uintn.h>

using namespace std;

/**
 * Tous les entiers que l'on manipule ici sont non signés. On définit deux
 * abbréviations pour unsigned int et unsigned long long. Plus confortable...
 */
typedef unsigned int uint;
typedef unsigned long long ullong;

/**
 * La classe registre permet de gérer un tableau de bits et y appliquer des opérations en arithmétique
 * binaire. Quelques facilités sont prévues pour rendre l'utilisation et les tests plus confortables
 * Attention : on fixe comme convention que le bit 0 est à gauche, le bits d'indice taille-1 est à droite.
 */
class Registre {
private:
    uint taille;   // longueur du registre
    ullong registre = 0; // valeur courante du registre (0 par défaut)
    
public:
    Registre() : taille(32) {} // Pour AES initialise
    Registre(uint taille);
    Registre(uint taille, const string& strVal); // strVal contient "0100111000..." une suite binaire représentée par des caractères
    Registre(uint t, uint32_t val);

    uint getTaille() const;

    void setValeur(const string& strVal); // Pour initialiser ou réinitialiser le registre

    uint get(uint numbit) const;
    unsigned char getByte(uint numbit) const;
    void set(uint numbit, uint b);
    void setByte(uint numbit, unsigned char b);

    void shiftL(uint nbbits = 1); // décalage à gauche d'un certain nombre de bits
    void rotationDeByte(); //[B0, B1, B2, B3] -> [B1, B2, B3, B0]

    Registre xtime() const; //Pour calculer AES chiffrement

    string toBin() const; // Renvoie la suite de caractères 0 et 1 correspondant à la valeur du registre
    string toHex() const;

    const Registre& operator=(const Registre& r);

    Registre XOR(const Registre&) const; // ET arithmétique entre 2 registres
    bool operator==(const Registre&) const; // 2 registres sont égaux s'ils ont la même taille et la même valeur
    friend ostream& operator<<(ostream& f, const Registre& r);
};


#endif //LFSR_REGISTRE_H
