#include <cmath>
#include <cstdio>
#include <vector>
#include <iostream>
#include <algorithm>
using namespace std;


int main() {
    int T, N, i;
    cin >> T;
    while(T--) {
        cin >> N;
        long long int s = 1;
        for (i = 1; i <= N; i++) {
            if(i % 2 == 0)
                s++;
            else
                s = 2*s;
        }
        cout << s << endl;
    }
    return 0;
}

