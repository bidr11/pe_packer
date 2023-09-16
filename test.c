#include<stdio.h>
#include<windows.h>

int main(int argc, char *argv[]) {
    printf("Hello World!\n");
    MessageBox(NULL, "Hello World!", "Hello World!", MB_OK);
    return 0;
}