#include<stdio.h>
#include<stdlib.h>
#include<string.h>
void main()
{
     char *a1=malloc(0x45);
     memset(a1,'a',0x45);
     char *a2=malloc(0x48);
     memset(a2,'b',0x48);
     char *a3=malloc(0x45);
     memset(a3,'c',0x45);
     char *a4=malloc(0x49);
     memset(a4,'d',0x49);
     char *a5=malloc(0x49);
     memset(a5,'e',0x49);
     printf("malloc down!\n");
     free(a1);
     free(a2);
     free(a3);
     free(a4);
}
