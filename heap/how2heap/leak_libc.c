#include <stdlib.h>
#include <stdio.h>

int main(int argc , char* argv[])
{
    long* t[7];
    long *a=malloc(0x100);
    long *b=malloc(0x10);
    getchar();
    // make tcache bin full
    for(int i=0;i<7;i++)
        t[i]=malloc(0x100);
    for(int i=0;i<7;i++)
        free(t[i]);

    free(a);
    // a is put in an unsorted bin because the tcache bin of this size is full
    printf("%p\n",a[0]);
} 
