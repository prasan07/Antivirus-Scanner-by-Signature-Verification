#include <iostream>
#include <cmath>
using namespace std;

int main()
{
        int n;
        int sum = 0;
        int nos;

        cout << "Enter count of numbers to sum\n";
        cin >> n;

        for (int i = 0; i < n; i++) {
                cout << "Enter number to sum\n";
                cin >> nos;

                sum += nos;
        }

        cout << "Sum = " << sum;
        return 0;
}
