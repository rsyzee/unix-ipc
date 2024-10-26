#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#define SOCK_PATH "/tmp/.unix_ipc"
#define BUFFER_SIZE 1024

static volatile int unix_sock_fd = -1;
volatile int g_need_exit = 0;
static void signal_cb()
{
    g_need_exit = 1;
}

int main()
{
    signal(SIGTERM, signal_cb);
    signal(SIGINT, signal_cb);

    unix_sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sock_addr;

    memset(&sock_addr, 0, sizeof(struct sockaddr_in));
    sock_addr.sun_family = AF_UNIX; 
    strncpy(sock_addr.sun_path, SOCK_PATH, sizeof(sock_addr.sun_path) - 1);

    if (connect(unix_sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)))
    {
        perror("client: failed attempt to connect() to the server");
        close(unix_sock_fd);
        return -1;
    }

    char buffer[1024];

    while (!g_need_exit) {
        if (fgets(buffer, BUFFER_SIZE, stdin) == NULL)
            break;

        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n')
            buffer[--len] = '\0';

    
        if (send(unix_sock_fd, buffer, len, 0) == -1) {
            perror("send");
            break;
        }

        ssize_t bytes_received = recv(unix_sock_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received < 0) {
                perror("client: failed to recv()");
            }

            break;
        }

        buffer[bytes_received] = '\0';
        printf("Server response: %s\n", buffer);
    }

    close(unix_sock_fd);
    return 0;
}