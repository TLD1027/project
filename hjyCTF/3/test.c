#include<stdio.h>
#include<stdlib.h>
int main(){
	int *p1 = malloc(0x10);
	int *p2 = malloc(0x20);
	int *p3 = malloc(0x30);
	int *p4 = malloc(0x40);
	int *p5 = malloc(0x50);
	int *p6 = malloc(0x60);
	int *p7 = malloc(0x70);
	int *p8 = malloc(0x100);
	free(p1);
	free(p2);
	free(p3);
	free(p4);
	free(p5);
	free(p6);
	free(p7);
	getchar();
	return 0;
}
