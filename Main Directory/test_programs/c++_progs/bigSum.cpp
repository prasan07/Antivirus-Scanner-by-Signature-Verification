#include<iostream>
#include<vector>

using namespace std;

int main() {
    int number_of_elements;
    cin >> number_of_elements;
    vector <int> array(number_of_elements);
    for (int i = 0; i < number_of_elements; i++) {
        cin >> array[i];
    }
        
    long long int sum_of_numbers = 0;
    for (int i = 0; i < number_of_elements; i++) {
        sum_of_numbers += array[i];
    }
    cout << sum_of_numbers << endl;
    return 0;
}
