#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_ARGS 1024

char** split_command(const char* command) {
    char **args = malloc(MAX_ARGS * sizeof(char*));
    char *token;
    int i = 0;

    char *command_copy = strdup(command);
    token = strtok(command_copy, " ");
    while (token != NULL && i < MAX_ARGS - 1) {
        args[i] = strdup(token);
        token = strtok(NULL, " ");
        i++;
    }
    args[i] = NULL;

    free(command_copy);
    return args;
}

int main(int argc, char *argv[]) {
    if (strcmp(argv[1], "childprocess") == 0) {
        printf("Spawning child process %s\n", argv[2]);
        char **command_args = split_command(argv[2]);
        
        pid_t pid = fork();
        if (pid == 0) {  // Child process
            execvp(command_args[0], command_args);
            perror("execvp");  // execvp will only return if there's an error
            exit(1);
        } else if (pid > 0) {  // Parent process
            wait(NULL);  // Wait for child process to finish
        } else {
            perror("fork");
            exit(1);
        }
    } else {
        for (int counter = 0; counter < argc; counter++)
            printf("argv[%2d]: %s\n", counter, argv[counter]);
        char *args[] = {"/bin/bash", NULL};
        execvp(args[0], args);
        perror("execvp");
    }
    return 0;
}
