//
//  shellListDir_code.c
//  shellPrograms
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//


#include "shellPrograms.h"

/*
	List the items in the directory
*/
int shellListDir_code(char** args)
{
	struct dirent **dirList;
	struct stat fileInfo;
	char buffer[80];
	int num_files = scandir(".", &dirList, filterHidden, sortFiles);
	printf("Hello from shellListDir_code. Unfortunately, 'listdir' hasn't been implemented yet.");
    return 1;
}

int filterHidden(const struct dirent *entry) 
{
	// we need to filter out all of the files that ought to be hidden; or maybe we could ignore it entirely...?
	return strncmp(entry->d_name, ".", 1);
}

int sortFiles(const struct dirent **a, const struct dirent **b)
{
	struct stat astat, bstat;

}

int main(int argc, char** args){
    return shellListDir_code(args);
}
