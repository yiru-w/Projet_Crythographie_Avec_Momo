//
// Created by lanuel on 26/01/2025.
//

#ifndef LFSR_LFSR_H
#define LFSR_LFSR_H


#include "Registre.h"

class LFSR {
private:
    Registre    registre;
    Registre    retroaction;

public:
    LFSR(uint taille); // On initiazlise juste la taille
    LFSR(uint taille, const string& retro, const string valinit); // On initialise tout

    const Registre& getRegistre() const;
    const Registre& getRetroaction() const;

    void setRetroaction(const Registre& retroaction);
    void setValeurInitiale(const string& valInit);

    uint getBitSortie() const;          // Sans commentaire
    uint getValeurRetroaction() const;  // calcul la valeur du bit de rétroaction par rapport à la valeur courante du registre
    void rotL(); // Réalise un cycle du LFSR

    string genererSequence(uint longueur);

    const LFSR& operator=(const LFSR&);
};


#endif //LFSR_LFSR_H
