//
//  shell.c
//  CSE_Codes
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//

#include "shell.h"
/*
  Builtin function implementations.
*/

int shellUsage (char** args)
{
  printf("Hello from shell.c. Unfortunately, shellUsage hasn't been implemented yet.\n");

  return 1;
}

/*
 List all files matching the name in args[1] under current directory and subdirectories
*/
int shellFind(char** args){
    
    if (execvp("./shellPrograms/find", args) == -1) {
        perror("Failed to execute, command is invalid.");
    }
    //This line will only be reached if execvp fails to create new process image
    return 1;
}


/**
 Allows one to display the content of the file
 */
int shellDisplayFile(char** args)
{
    if (execvp("./shellPrograms/display", args) == -1) {
        perror("Failed to execute, command is invalid.");
    }
    //This line will only be reached if execvp fails to create new process image
    return 1;
}

/*
	List the items in the directory and subdirectory
*/
int shellListDirAll(char** args)
{
    
    if (execvp("./shellPrograms/listdirall", args) == -1) {
        perror("Failed to execute, command is invalid.");
    }
    //This line will only be reached if execvp fails to create new process image
    return 1;

}

/*
	List the items in the directory
*/
int shellListDir(char** args)
{
    if (execvp("./shellPrograms/listdir", args) == -1) {
        perror("Failed to execute, command is invalid.");
    }
    
    //This line will only be reached if execvp fails to create new process image
    return 1;
}

/**
   Counts how many lines are there in a text file. 
   A line is terminated by \n character
**/
int shellCountLine(char** args){
    if (execvp("./shellPrograms/countline", args) == -1) {
        perror("Failed to execute, command is invalid.");
    }
    
    //This line will only be reached if execvp fails to create new process image
    return 1;
}


/**
   Allows one to change directory 
 */
int shellCD(char **args)
{
  if (args[1] == NULL) {
    fprintf(stderr, "CSEShell: expected argument to \"cd\"\n");
  } else {
    if (chdir(args[1]) != 0) {
      perror("CSEShell:");
    }
  }
  return 1;
}

/**
   Prints out the usage and
   list of commands implemented
 */
int shellHelp(char **args)
{
  int i;
  printf("CSE Shell Interface\n");
  printf("Usage: command arguments\n");
  printf("The following commands are implemented:\n");

  for (i = 0; i < numOfBuiltinFunctions(); i++) {
    printf("  %s\n", builtin_commands[i]);
  }

  return 1;
}

/**
   @brief Builtin command: exit.
   @param args List of args.  Not examined.
   @return Always returns 0, to terminate execution from the shellLoop
 */
int shellExit(char **args)
{
  return 0;
}


/*
  End of builtin function implementations.
*/

/**
   Execute inputs when its in the default functions
   Otherwise, error, refer them to help
 */
int shellExecuteInput(char **args)
{
  int i, status;
  pid_t pid;
    
  if (args[0] == NULL) {
    // An empty command was entered.
    return 1;
  }


  // Check if the commands exist in the command list
  for (i = 0; i < numOfBuiltinFunctions(); i++) {
    if (strcmp(args[0], builtin_commands[i]) == 0) {
        if (i != 0 && i!=1 && i!=2 && i!=3){
            //create new process to run the function with the specific command
            //except for cd, help, and exit. These three have to be done in your this process space
            pid = fork();
            if (pid == 0){
                int status = (*builtin_commandFunc[i])(args);
                exit(status);
            }
            else if (pid < 0)
            {
                perror("Fork doesn't work, exiting Program.");
            }
            else{
                //wait until process has finished running
                waitpid(pid, &status, WUNTRACED);
                return status;
            }
        }
        else{
            return (*builtin_commandFunc[i])(args);
        }
      
    }
  }

  //otherwise print error message
  printf("Invalid command received. Type help to see what commands are implemented. \n");
  return 1;

}

/**
   Read line from stdin, return it to the Loop function to tokenize it
 */
char *shellReadLine(void)
{
  size_t bufsize = SHELL_BUFFERSIZE;
  int position = 0;
  char *line = malloc(sizeof(char) * SHELL_BUFFERSIZE);
  int c;

  if (!line) {
    fprintf(stderr, "Allocation error for input buffer. Exiting program.\n");
    exit(EXIT_FAILURE);
  }

  //dont use scanf, will stop at whitespace character, it should be used only on formatted input
  getline(&line, &bufsize, stdin);

  return line;
}


char **shellTokenizeInput(char *line)
{
  int bufsize = SHELL_BUFFERSIZE, position = 0;
  char **tokens = malloc(bufsize * sizeof(char*)); //an array of pointers to the first char that marks a token in line
  char *token, **tokens_backup;


  if (!tokens) {
    fprintf(stderr, "Allocation error encountered. Exiting program.\n");
    exit(EXIT_FAILURE);
  }

  /*
     Tokenize the line, and store it at **tokens
  */
  token = strtok(line, SHELL_INPUT_DELIM);
  tokens[position] = token;
  position++;

  while (token != NULL) {
  	// Tokenize the rest of the inputs
    token = strtok(NULL, SHELL_INPUT_DELIM);
    tokens[position] = token;
    position++;

  }

  //adds NULL termination at the end 
  tokens[position] = NULL;
  return tokens;
}

/**
  The main loop where one reads line,
  tokenize it, and then executes the command
 */
void shellLoop(void)
{
  char *line;
  char **args;
  int status;

  do {
    printf("CSEShell> ");
    fflush(stdout);
    fflush(stdin);
    line = shellReadLine();
    args = shellTokenizeInput(line);
    status = shellExecuteInput(args);

    free(line);
    free(args);
  } while (status);
}


int main(int argc, char **argv)
{

  // Run command loop
  shellLoop();

  return 0;
}


