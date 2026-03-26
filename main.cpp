#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <iterator>
#include "AES.h"
#include "Registre.h"

// Convertit une chaîne Hexa en vecteur d'octets
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Affiche un MAC en hex et l'écrit dans le fichier de sortie
void printMAC(const std::string& label, const std::vector<uint8_t>& mac) {
    std::cout << label << " : ";
    for (uint8_t b : mac) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << std::endl;
}

void printUsage() {
    std::cout << "Usage: aes_app [action] [mode] [key_hex] [input_file] [output_file]" << std::endl;
    std::cout << std::endl;
    std::cout << "Actions :" << std::endl;
    std::cout << "  -e   Chiffrement" << std::endl;
    std::cout << "  -d   Dechiffrement" << std::endl;
    std::cout << "  -m   Calcul du MAC" << std::endl;
    std::cout << std::endl;
    std::cout << "Modes :" << std::endl;
    std::cout << "  -ecb   Electronic Code Book" << std::endl;
    std::cout << "  -cbc   Cipher Block Chaining (iv_hex requis pour -e et -d)" << std::endl;
    std::cout << std::endl;
    std::cout << "Exemples :" << std::endl;
    std::cout << "  aes_app -e -ecb 2b7e151628aed2a6abf7158809cf4f3c message.txt cipher.bin" << std::endl;
    std::cout << "  aes_app -d -ecb 2b7e151628aed2a6abf7158809cf4f3c cipher.bin output.txt" << std::endl;
    std::cout << "  aes_app -m -ecb 2b7e151628aed2a6abf7158809cf4f3c message.txt mac.bin" << std::endl;
    std::cout << "  aes_app -e -cbc 2b7e151628aed2a6abf7158809cf4f3c message.txt cipher.bin 000102030405060708090a0b0c0d0e0f" << std::endl;
    std::cout << "  aes_app -d -cbc 2b7e151628aed2a6abf7158809cf4f3c cipher.bin output.txt 000102030405060708090a0b0c0d0e0f" << std::endl;
    std::cout << "  aes_app -m -cbc 2b7e151628aed2a6abf7158809cf4f3c message.txt mac.bin" << std::endl;
}



int main(int argc, char* argv[]) {
    if (argc < 6) {
        printUsage();
        return 1;
    }

    string action     = argv[1];
    string mode       = argv[2];
    string keyHex     = argv[3];
    string inputFile  = argv[4];
    string outputFile = argv[5];

    // 1. Conversion de la clé Hexa -> vector<unsigned char>
    vector<unsigned char> keyBytes = hexToBytes(keyHex);
    if (keyBytes.size() != 16) {
        cerr << "Erreur : La cle doit faire 16 octets (32 caracteres hexa)." << endl;
        return 1;
    }

    // 2. Préparation de la clé pour ton constructeur (vector<Registre>)
    vector<Registre> keyRegs;
    for (int i = 0; i < 4; i++) {
        uint32_t val = (keyBytes[i*4] << 24) | (keyBytes[i*4+1] << 16) |
                       (keyBytes[i*4+2] << 8) | keyBytes[i*4+3];
        keyRegs.push_back(Registre(32, val));
    }

    // 3. Lecture du fichier d'entrée
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Erreur: Impossible de lire le fichier " << inputFile << endl;
        return 1;
    }
    vector<unsigned char> inputData((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    inFile.close();

    try {
        // 4. Initialisation de ton objet AES
        AES aes(keyRegs);
        vector<unsigned char> resultData;

        // 5. Appel de tes fonctions spécifiques
        if (mode == "-ecb") {
            if (action == "-e") {
                resultData = aes.ChiffrementECB(inputData);
                cout << "Chiffrement ECB termine avec succes." << endl;
            }
            else if (action == "-d") {
                resultData = aes.DechiffrementECB(inputData);
                cout << "Dechiffrement ECB termine avec succes." << endl;
            }
            else if (action == "-m") {
                resultData = aes.ChiffrementECB_MAC(inputData);
                cout << "ECB-MAC : ";
                for (unsigned char b : resultData)
                    cout << hex << setw(2) << setfill('0') << (int)b;
                cout << dec << endl;
            }
            else {
                cerr << "Action non reconnue (-e ou -d)." << endl;
                return 1;
            }
        }else if (mode == "-cbc") {
            if (action == "-e") {
                resultData = aes.ChiffrementCBC(inputData);
                cout << "Chiffrement CBC-MAC termine avec succes." << endl;
            } else if (action == "-d") {
                resultData = aes.DechiffrementCBC_MAC(inputData);
                cout << "Dechiffrement CBC-MAC termine avec succes." << endl;
            }
            else if (action == "-m") {
                resultData = aes.ChiffrementCBC_MAC(inputData);
                cout << "CBC-MAC : ";
                for (unsigned char b : resultData)
                    cout << hex << setw(2) << setfill('0') << (int)b;
                cout << dec << endl;
            }
            else {
                cerr << "Action non reconnue (-e ou -d ou -m)." << endl;
                return 1;
            }
        }
        else {
            cerr << "Seul le mode -ecb est supporte pour le moment." << endl;
            return 1;
        }

        // 6. Écriture du résultat dans le fichier de sortie
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cerr << "Erreur: Impossible d'ecrire dans " << outputFile << endl;
            return 1;
        }
        outFile.write(reinterpret_cast<const char*>(resultData.data()), resultData.size());
        outFile.close();

        cout << "Fichier enregistre sous : " << outputFile << endl;

    } catch (const exception& e) {
        cerr << "Erreur critique : " << e.what() << endl;
        return 1;
    }
    return 0;
}
