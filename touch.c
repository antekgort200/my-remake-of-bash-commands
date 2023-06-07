#include<stdio.h>
int main(int argc, char* argv[]){
	FILE *fptr;
	fptr = fopen(argv[1],"w");
	fclose(fptr);
	return 0;
}
