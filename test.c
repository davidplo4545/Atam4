//
// Created by david on 6/29/2023.
//
#include <stdio.h>
int x = 0;
int foo()
{
    x +=1;
    return x;
}
int main()
{
    for(int i=0;i<3;i++) foo();
    printf("david\n");
    return 0;
}
