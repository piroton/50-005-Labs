//
//  shellCountLine_code.c
//  shellPrograms
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//



#include "shellPrograms.h"

int shellCountLine_code(char** args)
{
	// printf("Hello from shellCountLine_code. Unfortunately, 'countline' hasn't been implemented yet.");
	int lineCounter = 0;
	char string[256];
	FILE *filepointer;


	filepointer = fopen(args[1], "r");  // returns pointer for file

	while (fgets(string, 256, filepointer) != NULL){
		// everytime fgets is called, one line of text is stored in 'string'. If we have reached end of file, it returns NULL.
		lineCounter++;
	}

	printf("There are %i lines in %s\n", lineCounter, args[1]);
	fclose(filepointer);

	return 1;
}

int main(int argc, char** args){
	return shellCountLine_code(args);
}
