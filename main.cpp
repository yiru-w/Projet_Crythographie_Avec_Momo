

#include "LFSR.h"
#include "Registre.h"
string toBin(const uint &nombre) {
    if (nombre == 0)
        return "0";
    if (nombre ==1)
        return "1";
    return toBin(nombre / 2) + char('0' + nombre % 2);
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


int main() {
    TestLFSR();

}
