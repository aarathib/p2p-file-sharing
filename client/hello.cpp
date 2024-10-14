#include <iostream>
#include <vector>
#include <unordered_map>

using namespace std;

int main()
{
    int n;
    cin >> n;

    vector<int> arr(n);
    for (int i = 0; i < n; i++)
    {
        cin >> arr[i];
    }

    int sum = 0, count = 0;
    unordered_map<int, int> presum;

    for (int i = 0; i < n; i++)
    {
        presum[i - sum] = i;
        int sum = 0;
        sum += arr[i];
        if (presum.find(sum - i - 1) != presum.end())
            count++;
    }

    cout << count;

    return 0;
}