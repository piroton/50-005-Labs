//
//  shellFind_code.c
//  shellPrograms
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//

#include "shellPrograms.h"
/*
 List all files matching the name in args[1] under current directory and subdirectories
*/
int shellFind_code(char** args)
{

    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (strstr(dir->d_name, args[1]) != NULL) {
                printf("%s\n", dir->d_name);
            }
        }
        closedir(d);
    }
}

int main(int argc, char** args){
    return shellFind_code(args);
}
