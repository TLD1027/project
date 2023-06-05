#include <stdio.h>  
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *password = "WelCome t0 t1D";
char *username = "admin";
int login = 0;

void _printf_(char *c) {
    if (*c >= 'a' && *c <= 'z' && *c % 2 == 0) {
        *c = *c + 2 > 'z' ? *c - 26 : *c + 2;
        *c = *c - 32;
    } else if (*c >= 'A' && *c <= 'Z' && *c % 2 == 0) {
        *c = *c + 2 > 'Z' ? *c - 26 : *c + 2;
        *c = *c + 32;
    } 
    printf("%s", c);
}

char* enCode(char *str) {
    int key[100]; 
    char *enc;
    srand(time(0));
    for(int i=0; i<strlen(str); i++){
        key[i] = rand() % 0xff;
    }
    enc = (char*)malloc(strlen(str)+1);
    int i;
    for (i=0; i<strlen(str); i++) {
        enc[i] = str[i] ^ key[i];
        // _printf_(&enc[i]);
    }
    enc[i] = '\00';
    return enc;
}

void init(){
    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    puts("Welcome to T1d's April Fool's Day game!");
    puts("Just have Fun~");
    puts("Please login at first~");
}

void menu(){
    puts("1.play a foolish game");
    puts("2.change your password");
    puts("3.give you a fmt");
    puts("4.do you know backdoor?");
    puts("5.exit");
    puts(">>>");
}

void fmt(){
  char str[16];
  puts("Are you good at fmt???");
  read(0, str, 16);
  if(strstr(str, "$")){
    puts("Badboy!!!!");
  }else{
    printf(str);
  }
}

void fun_game(){
  char buf[32];
  read(0, buf, 100);
}

void change_password(){
  puts("a");
}

void vuln(){
    int i;
    while (1) {
    menu();
    scanf("%d", &i);
    switch (i) {
    case 5:
      fun_game();
      break;
    case 4:
      change_password();
      break;
    case 3:
      fmt();
      break;
    case 2:
      puts("you think beautiful~");
      break;
    case 1:
      exit(0);
      break;
    default:
      printf("invalid input\n");
      break;
    }
  }
}

int backdoor(){
    system("/bin/sh");
    return 0;
}

int main(){
    init();
    char str1[64];
    char str2[64];
    printf("please input your username:");
    read(0, str1, 64);
    char *user = enCode(str1);
    printf("please input your password:");
    read(0, str2, 64);
    char *pass = enCode(str2);
    if(!strcmp(pass, password) && !strcmp(user, username)){
        puts("Welcome! my friend!!!");
        vuln();
    }else{
        puts("Wrong!!!YOU ARE NOT MY FRIEND!!");
        exit(1);
    }
    return 0; 
}