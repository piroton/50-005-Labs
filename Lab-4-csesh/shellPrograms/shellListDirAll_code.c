//
//  shellListDirAll_code.c
//  shellPrograms
//
//  Created by Natalie Agus on 11/01/19.
//  Copyright © 2019 Natalie Agus. All rights reserved.
//


#include "shellPrograms.h"

int shellListDirAll_code(char** args)
{
    /**
     * DIR *directory;
    struct dirent *dirEntry;

	if (strcmp(args, "") == 0 ){
        directory = opendir(".");
        indent = 0;
    } else {
        directory = opendir(args[0]);
        indent = 2;
    }

    if (!directory) {
        printf("Error opening directory!");
        return -1;
    }
    while ((dirEntry = readdir(directory))!= NULL){
        if (dirEntry->d_type == DT_DIR){
            char path[1024];
            if (strcmp(dirEntry->d_name, ".")==0 || strcmp(dirEntry->d_name, "..")==0){
                continue;
            }
            snprintf(path, sizeof(path), "%s%s", args[0], dirEntry -> d_name);
            printf("%*s[%s]\n", indent, "", dirEntry -> d_name);
            shellListDirAll_code(**path);
        } else {
            printf("%*s%s\n", indent, "", dirEntry->d_name);
        }
    }
    closedir(directory);
    return 1;
    **/
    // Actually, all we need to do is this:
    char path[80] = ".";
    ftw(".", printName, 100);
    return 1;
}

int printName(const char * ftw_filePath, const struct stat * ptr, int flags){
    FILE * file;
    char * fileName;
    fileName = strdup(ftw_filePath);

    if (fileName == NULL || strlen(fileName)==0){
        free(fileName);
        return 1;
    }
    printf("%s\n",fileName);
    return 0;
}

int main(int argc, char** args){
    return shellListDirAll_code(args);
}
