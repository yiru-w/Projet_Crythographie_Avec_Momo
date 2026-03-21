

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
        // --- 1. 定义标准测试密钥 (128-bit) ---
        // Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e f
        vector<Registre> key;
        key.push_back(Registre(32, 0x00010203));
        key.push_back(Registre(32, 0x04050607));
        key.push_back(Registre(32, 0x08090a0b));
        key.push_back(Registre(32, 0x0c0d0e0f));

        AES aes(key);

        // --- 2. 定义标准明文 ---
        // Plaintext: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
        Registre state[4];
        state[0] = Registre(32, 0x00112233);
        state[1] = Registre(32, 0x44556677);
        state[2] = Registre(32, 0x8899aabb);
        state[3] = Registre(32, 0xccddeeff);

        cout << "--- TEST AES 128-BIT ---" << endl;
        printState("Plaintext ", state);

        // --- 3. 执行加密 ---
        aes.chiffrement(state);
        printState("Ciphertext", state);
        cout << "Attendu   : 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a" << endl;

        // --- 4. 执行解密 ---
        aes.Dechiffrement(state);
        printState("Decrypted ", state);

    } catch (const exception& e) {
        cerr << "Erreur : " << e.what() << endl;
    }
}

int main() {
    //TestLFSR();
    TestAES();
}
