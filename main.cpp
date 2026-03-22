

#include <iomanip>
#include <vector>

#include "AES.h"
#include "LFSR.h"
#include "Registre.h"
string toBin(const uint &nombre) {
    if (nombre == 0)
        return "0";
    if (nombre ==1)
        return "1";
    return toBin(nombre / 2) + char('0' + nombre % 2);
}

// Fonction auxiliaire : Convertir une chaîne Hexa en vector<unsigned char>
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Fonction auxiliaire : Afficher les données en format Hexadécimal
void printHex(const string& label, const vector<unsigned char>& data) {
    cout << label << ": ";
    for (unsigned char b : data) {
        cout << hex << setw(2) << setfill('0') << (int)b;
    }
    cout << dec << endl;
}

void printState(const string& label, Registre state[4]) {
    cout << label << ": ";
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            cout << hex << setfill('0') << setw(2) << (int)state[i].getByte(j) << " ";
        }
    }
    cout << endl;
}

void TestRegistre() {
    Registre r(5,"01101");
    Registre r2(5,"01101");
    if (r == r2) {
        cout << "r = r2 est vrai" << endl;
    }
    else {
        cout << "r = r2 est faux" << endl;
    }
    uint bit = r.get(0);
    r.set(1,0);
    cout << toBin(bit) << endl;
    cout << "Registre bit: " << r << endl; // set 01101 a 00101
    r.shiftL(3);
    cout << "Registre decaler gauche : " << r << endl; // 00101 -> 3 gauche -> 01000

    Registre r3(5);
    r3 = r.XOR(r2);
    cout << "Registre apres XOR : " << r3 << endl;
}

void TestLFSR() {
    LFSR lfsr(4, "1001","1111");
    string mot = lfsr.genererSequence(20);
    cout << "Le mot est : " << mot << endl;
}

void TestAES() {
    try {

        // Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e f
        vector<Registre> key;
        key.push_back(Registre(32, 0x00010203));
        key.push_back(Registre(32, 0x04050607));
        key.push_back(Registre(32, 0x08090a0b));
        key.push_back(Registre(32, 0x0c0d0e0f));

        AES aes(key);

        // Plaintext: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
        Registre state[4];
        state[0] = Registre(32, 0x00112233);
        state[1] = Registre(32, 0x44556677);
        state[2] = Registre(32, 0x8899aabb);
        state[3] = Registre(32, 0xccddeeff);

        cout << "--- TEST AES 128-BIT ---" << endl;
        printState("Plaintext ", state);

        aes.chiffrement(state);
        printState("Ciphertext", state);
        cout << "Attendu   : 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a" << endl;

        aes.Dechiffrement(state);
        printState("Decrypted ", state);

    } catch (const exception& e) {
        cerr << "Erreur : " << e.what() << endl;
    }
}

void TestECB() {
    // 1. Vecteurs de test NIST (SP 800-38A, Appendix F.1.1)
    // Clé : 2b7e151628aed2a6abf7158809cf4f3c
    string keyHex = "2b7e151628aed2a6abf7158809cf4f3c";
    // Texte clair : 6bc1bee22e409f96e93d7e117393172a
    string plainHex = "6bc1bee22e409f96e93d7e117393172a";

    // 2. Conversion des données
    vector<unsigned char> keyBytes = hexToBytes(keyHex);
    vector<unsigned char> plainBytes = hexToBytes(plainHex);

    // Conversion de la clé en vector<Registre> (4 registres de 32 bits)
    vector<Registre> keyRegs;
    for (int i = 0; i < 4; i++) {
        uint32_t val = (keyBytes[i*4] << 24) | (keyBytes[i*4+1] << 16) |
                       (keyBytes[i*4+2] << 8) | keyBytes[i*4+3];
        keyRegs.push_back(Registre(32, val));
    }

    try {
        // 3. Initialisation de l'objet AES
        AES aes(keyRegs);

        // 4. Exécution du Chiffrement ECB
        vector<unsigned char> cipherBytes = aes.ChiffrementECB(plainBytes);

        // 5. Exécution du Déchiffrement ECB
        vector<unsigned char> decryptedBytes = aes.DechiffrementECB(cipherBytes);

        // 6. Affichage des résultats pour comparaison
        cout << "--- Test NIST ECB (AES-128) ---" << endl;
        printHex("Chiffré Attendu ", hexToBytes("3ad77bb40d7a3660a89ecaf32466ef97"));
        printHex("Chiffré Obtenu  ", cipherBytes);
        cout << endl;
        printHex("Texte Original  ", plainBytes);
        printHex("Texte Déchiffré ", decryptedBytes);

        // 7. Vérification finale
        if (cipherBytes == hexToBytes("3ad77bb40d7a3660a89ecaf32466ef97")) {
            cout << "\n[SUCCÈS] Le résultat est conforme au standard NIST !" << endl;
        } else {
            cout << "\n[ÉCHEC] Le résultat est incorrect. Vérifiez MixColumns ou KeyExpansion." << endl;
        }

    } catch (const exception& e) {
        cerr << "Erreur : " << e.what() << endl;
    }
}

int main() {
    //TestLFSR();
    //TestAES();
    TestECB();
}
