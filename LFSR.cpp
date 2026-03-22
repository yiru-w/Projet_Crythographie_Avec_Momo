//
// Created by lanuel on 26/01/2025.
//

#include "LFSR.h"

#include <sstream>

LFSR::LFSR(uint taille) : registre(taille), retroaction(taille){}

LFSR::LFSR(uint taille, const string& retro, const string vinit)
    : registre(taille, vinit), retroaction(taille, retro)
{}

const Registre& LFSR::getRegistre() const {
    return registre;
}
const Registre& LFSR::getRetroaction() const {
    return retroaction;
}

void LFSR::setRetroaction(const Registre& retroaction) {
    this->retroaction = retroaction;
}
void LFSR::setValeurInitiale(const string& valInit) {
    this->registre.setValeur(valInit);
}

uint LFSR::getBitSortie() const {
    return registre.get(0);
}

/**
 *
 * @return On return le XOR du valeur plus a gauche et a droit
 */
uint LFSR::getValeurRetroaction() const {
    uint resultat = 0 ;
    for (uint i = 0; i < retroaction.getTaille(); i++) {
        if (retroaction.get(i) == 1) {
            resultat ^= registre.get(i);
        }
    }
    return resultat;
}

void LFSR::rotL() {
    const uint bit = getValeurRetroaction();
    registre.shiftL(1);
    registre.set(registre.getTaille()-1, bit);
}

const LFSR& LFSR::operator=(const LFSR& lfsr) {
    if (this == &lfsr)
        return lfsr;

    this->registre = lfsr.registre;
    this->retroaction = lfsr.retroaction;

    return *this;
}

string LFSR::genererSequence(uint longueur) {
    ostringstream str;
    for (uint i = 1; i <=    longueur; i++) {
        uint valeur = getBitSortie();
        str << valeur;
        rotL();
    }
    return str.str();
}