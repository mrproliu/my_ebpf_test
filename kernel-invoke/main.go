package main

/*
#include <stdio.h>

void demo(){
	printf("HELLO WORLD! \n");
}
*/
import "C"

func main() {
	C.demo()
}
