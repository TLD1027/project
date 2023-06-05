#include<stdio.h>
int sum(int* input, int length) {
	int sum = 0;
	for (int i = 0; i < length; i++) {
		sum += input[i];
	}
	return sum;
}
int main()
{
	int a[2] = {1,2};
	printf("%d", sum(a, 2));
	return 0;
}
