package main

/*
#include <stdio.h>

struct ksym {
	long addr;
	char *name;
};
#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];
void demo(){
	printf("HELLO WORLD! \n");
}
*/
import "C"

func main() {
	C.demo()
}
