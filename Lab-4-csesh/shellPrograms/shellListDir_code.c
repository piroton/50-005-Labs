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
	int num_files = scandir(".", &dirList, filterHidden, sortFiles);
	if (num_files < 0) return -1;
	for (int i = 0; i < num_files; i++){
		printf("%s\n", dirList[i] -> d_name);
	}
    return 1;
}

int filterHidden(const struct dirent *entry) 
{
	// we need to filter out all of the files that ought to be hidden; or maybe we could ignore it entirely...?
	return strncmp(entry->d_name, ".", 1);
}

int sortFiles(const struct dirent **a, const struct dirent **b)
{
	return alphasort(a,b);
}

int main(int argc, char** args){
    return shellListDir_code(args);
}
