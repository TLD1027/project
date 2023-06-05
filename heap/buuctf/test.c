#include<stdio.h>
int main(){
    FILE *stream = fopen("/flag", "r");
    printf("%d\n", stream);
    char s[100];
    fgets(s, 45, stream);
    printf("%s", s);
}
