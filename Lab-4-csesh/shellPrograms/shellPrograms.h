//
//  shellPrograms.h
//  shellPrograms
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//


#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <dirent.h>
#include <errno.h>
/* "readdir" etc. are defined here. */
#include <dirent.h>
/* limits.h defines "PATH_MAX". */
#include <limits.h>
#include <ftw.h>

#define SHELL_BUFFERSIZE 256
#define SHELL_INPUT_DELIM " \t\r\n\a"
#define SHELL_OPT_DELIM "-"

/*
Implemented functions of the shell interface
*/
int shellDisplayFile_code(char** args);
int shellCountLine_code(char** args);
int shellListDir_code(char** args);
int filterHidden(const struct dirent *entry);
int sortFiles(const struct dirent **a, const struct dirent **b);
int shellListDirAll_code(char** args);
int printName(const char * ftw_filePath, const struct stat * ptr, int flags);
int shellFind_code(char** args);
