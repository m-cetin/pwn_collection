#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void pwncollege(){
    return;
}

void executeCommand(const char *command, int *inputPipe, int *outputPipe) {
    pid_t pid = fork();

    if (pid == -1) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        if (inputPipe != NULL) {
            dup2(inputPipe[0], STDIN_FILENO);
            close(inputPipe[0]);
            close(inputPipe[1]);
        }

        if (outputPipe != NULL) {
            dup2(outputPipe[1], STDOUT_FILENO);
            close(outputPipe[0]);
            close(outputPipe[1]);
        }

        execlp(command, command, NULL);
        perror("Exec failed");
        exit(EXIT_FAILURE);
    }
}

int main() {
    int pipe1[2], pipe2[2];
    if (pipe(pipe1) == -1 || pipe(pipe2) == -1) {
        perror("Pipe creation failed");
        exit(EXIT_FAILURE);
    }

    write(pipe1[1], "oprqmylg\n", 9);
    executeCommand("/bin/cat", pipe1, pipe2);
    executeCommand("/challenge/embryoio_level64", pipe2, NULL);

    close(pipe1[0]);
    close(pipe1[1]);
    close(pipe2[0]);
    close(pipe2[1]);

    wait(NULL);
    wait(NULL);
    wait(NULL);

    return EXIT_SUCCESS;
}
