#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#define SOCK_PATH "/tmp/.unix_ipc"
#define BUFFER_SIZE 1024

volatile int g_need_exit = 0;
static volatile int server_fd = -1;
static void signal_cb()
{
    g_need_exit = 1;
}

int main()
{
    signal(SIGTERM, signal_cb);
    signal(SIGINT, signal_cb);
    
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
    {
        perror("sock()");
        return -1; 
    }

    int sock_opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(int)) < 0)
        return -1;

    struct sockaddr_un sock_addr;

    memset(&sock_addr, 0, sizeof(struct sockaddr_in));
    sock_addr.sun_family = AF_UNIX; 
    strncpy(sock_addr.sun_path, SOCK_PATH, sizeof(sock_addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)))
    {
        perror("bind()");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 5) == -1) {
        perror("listen()");
        return -1;
    }


    int client_fd = 0;
    char buffer[BUFFER_SIZE];
    while (!g_need_exit)
    {
        if ((client_fd = accept(server_fd, 0, 0)) == -1)
            continue;

         printf("server: client acceppted\n");

        
        while (1) 
        {
            ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) {

                if (bytes_received < 0)
                    perror("server: failed to recv()");
                break;
            }

            buffer[bytes_received] = '\0';
            printf("server: Received Message : %s\n", buffer);

            const char* temp_str = "Yes yes, I received your message";
            if (send(client_fd, temp_str, strlen(temp_str), 0) == -1) 
            {
                perror("server: fail to send()");
                break;
            }
        }

        close(client_fd);
        printf("server: Client disconnected\n");

    }

    close(server_fd);
    unlink(SOCK_PATH);
    return 0;
}