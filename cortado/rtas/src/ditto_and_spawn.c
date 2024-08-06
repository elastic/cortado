#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char * combineargv(int argc, char **argv)
{
    int totalsize = 0;
    for (int i = 2; i < argc; i++)
    {
       totalsize += strlen(argv[i]);
    }
    // Provides space for ' ' after each argument and a '\0' terminator.
    char *ret = malloc(totalsize + argc + 1);
    if (NULL == ret)
    {
        // Memory allocation error.
    }
    for (int i = 2; i < argc; i++)
    {
        strcat(ret, argv[i]);
        strcat(ret, " ");
    }
    return ret;
}

int main(int argc, char *argv[])
{
	int counter;
	if (strcmp(argv[1], "childprocess")==0){
		printf("Spawning child process %s\n",argv[2]);
		for(counter=2; counter<argc; counter++)
			printf("argv[%2d]: %s\n",counter,argv[counter]);
		char * command = combineargv(argc, argv);
		system(command);
	} else {
		for(counter=0; counter<argc; counter++)
			printf("argv[%2d]: %s\n",counter,argv[counter]);

    	system("/bin/bash");
	}

	return 0;
}
