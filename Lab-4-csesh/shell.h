//
//  shell.h
//  CSE_Codes
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//


#include <sys/wait.h>
#include <sys/types.h>
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


#define SHELL_BUFFERSIZE 256
#define SHELL_INPUT_DELIM " \t\r\n\a"
#define SHELL_OPT_DELIM "-"

/*
Implemented functions of the shell interface
*/
int shellCD(char **args);
int shellHelp(char **args);
int shellExit(char **args);
int shellDisplayFile(char** args);
int shellCountLine(char** args);
int shellListDir(char** args);
int shellListDirAll(char** args);
int shellFind(char** args);
int shellUsage (char** args);

/*
The fundamental functions of the shell interface
*/
void shellLoop(void);
char **shellTokenizeInput(char *line);
char *shellReadLine(void);
int shellExecuteInput(char **args);

/*
  List of builtin commands, followed by their corresponding functions.
 */
char *builtin_commands[] = {
  "cd",
  "help",
  "exit",
  "usage",
  "display",
  "countline",
  "listdir",
  "listdirall",
  "find",
};


/*This is array of functions, with argument char***/
int (*builtin_commandFunc[]) (char **) = {
  &shellCD, //builtin_commandFunc[0]
  &shellHelp, //builtin_commandFunc[1]
  &shellExit, //builtin_commandFunc[2]
  &shellUsage,//builtin_commandFunc[3]
  &shellDisplayFile, //builtin_commandFunc[4]
  &shellCountLine, //builtin_commandFunc[5]
  &shellListDir, //builtin_commandFunc[6]
  &shellListDirAll, //builtin_commandFunc[7]
  &shellFind, //builtin_commandFunc[8]

};

int numOfBuiltinFunctions() {
  return sizeof(builtin_commands) / sizeof(char *);
};

/*Helper functions*/
char* concat(const char *s1, const char *s2);
