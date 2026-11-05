#include <bits/stdc++.h>
using namespace std;

int num = 10;
char str[]    = "zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9";
char String[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main() {
    int len = strlen(str);

    // undo fcn.00401030 (case swap)
    for (int i = 0; i < len; i++)
        if (str[i] >= 'a' && str[i] <= 'z') str[i] -= 32;
        else if (str[i] >= 'A' && str[i] <= 'Z') str[i] += 32;

    // rebuild the scrambled table exactly like fcn.00401000
    for (int result = 6; result < 15; result++) {
        int v1 = String[result];
        String[result] = String[result + num];
        String[result + num] = v1;
    }

    cout << str << endl << String << endl;
    // from here: feed `str` + `String` into any standard base64 decoder
    // that accepts a custom alphabet, or finish with the 6-bit unpacking
    // loop shown in the Python "Strategy A" section above.
    return 0;
}