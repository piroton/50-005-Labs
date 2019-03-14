//
//  shellDisplayFile_code.c
//  shellPrograms
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//


#include "shellPrograms.h"

/**
   Allows one to display the content of the file 
 */
int shellDisplayFile_code(char** args)
{    
	printf("Hello from shellDisplayFile_code. Unfortunately, 'display' hasn't been implemented yet.");

	char string[256];
	FILE *filepointer;

	filepointer = fopen(args[1], "r");
	while (fgets(string, 256, filepointer) != NULL){
		printf("%s",string);
	}
	fclose(filepointer);

	printf("\n");
	return 1;
}

int main(int argc, char** args){
	return shellDisplayFile_code(args);
}
