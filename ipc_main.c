#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>

#include "ipc_proto.h"
#include "csum.h"

static volatile int g_need_exit = 0;


static void signal_cb(int signum)
{
    printf("signal %d detected\n", signum);

     if (signum == SIGINT) {
            g_need_exit = 1;
        }
}

static int _reg_sigaction(void)
{       
        struct sigaction sa;
        int ret;
        
        memset(&sa, 0, sizeof(struct sigaction));

        sa.sa_handler = signal_cb;

        ret = sigaction(SIGINT, &sa, NULL);
        if (ret < 0) {
                return -1;
        }

        ret = sigaction(SIGPIPE, &sa, NULL);

        return 0;
}

static void ipc_ctx_cleanup(struct unix_ipc_ctx *ctx)
{
    if (!ctx)
        return;

    close(ctx->fd);
    free(ctx);
    ctx = NULL;
}

static struct unix_ipc_ctx *init_ipc_srv_ctx(const struct ipc_config* ipc_proto_config) {
    if (!ipc_proto_config || !ipc_proto_config->socket_path) return NULL;

    struct unix_ipc_ctx* ctx = calloc(1, sizeof(struct unix_ipc_ctx));
    if (!ctx) return NULL;

    ctx->max_msg_size = ipc_proto_config->max_msg_size;
    ctx->protocol_version = ipc_proto_config->protocol_version;
    ctx->error_handler = ipc_proto_config->error_handler;
    ctx->is_server = 1;

    ctx->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ctx->fd == -1) {
        HANDLE_ERROR(ctx, "Failed to create socket", errno);
        free(ctx);
        return NULL;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX
    };
    
    strncpy(addr.sun_path, ipc_proto_config->socket_path, sizeof(addr.sun_path) - 1);

    unlink(ipc_proto_config->socket_path);

    if (bind(ctx->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        HANDLE_ERROR(ctx, "Failed to bind socket", errno);
        ipc_ctx_cleanup(ctx);
        return NULL;
    }

    if (listen(ctx->fd, 5) == -1) {
        HANDLE_ERROR(ctx, "Failed to listen on socket", errno);
        ipc_ctx_cleanup(ctx);
        return NULL;
    }

    return ctx;
}

struct unix_ipc_ctx *init_ipc_client_ctx(const struct ipc_config* ipc_proto_config) {
    if (!ipc_proto_config || !ipc_proto_config->socket_path) return NULL;

    struct unix_ipc_ctx* ctx = calloc(1, sizeof(struct unix_ipc_ctx));
    if (!ctx) return NULL;

    ctx->max_msg_size = ipc_proto_config->max_msg_size;
    ctx->protocol_version = ipc_proto_config->protocol_version;
    ctx->error_handler = ipc_proto_config->error_handler;
    ctx->is_server = 0;

    ctx->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ctx->fd == -1) {
    
        HANDLE_ERROR(ctx, "Failed to create socket", errno);
        free(ctx);
        return NULL;
    }

    ctx->stream_fd = ctx->fd;

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX
    };
    
    strncpy(addr.sun_path, ipc_proto_config->socket_path, sizeof(addr.sun_path) - 1);

    if (connect(ctx->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        HANDLE_ERROR(ctx, "Failed to connect", errno);
        ipc_ctx_cleanup(ctx);
        return NULL;
    }
    

    return ctx;
}

static int ipc_send_msg(struct unix_ipc_ctx *ipc_handle, struct ipc_message_pool* msg) {
    if (!ipc_handle || !msg || !msg->payload) return -1;

    // Validate message
    if (msg->header.magic != IPC_MAGIC ||
        msg->header.version != ipc_handle->protocol_version ||
        msg->header.payload_len > ipc_handle->max_msg_size) {
        HANDLE_ERROR(ipc_handle, "Invalid message", EINVAL);
        return -1;
    }

    // Send header
    ssize_t sent = send(ipc_handle->stream_fd, &msg->header, sizeof(struct ipc_message_header), MSG_NOSIGNAL);
    if (sent != sizeof(struct ipc_message_header)) {
        HANDLE_ERROR(ipc_handle, "Failed to send header", errno);
        return -1;
    }

    // Send payload
    sent = send(ipc_handle->stream_fd, msg->payload, msg->header.payload_len, MSG_NOSIGNAL);
    if (sent != msg->header.payload_len) {
        HANDLE_ERROR(ipc_handle, "Failed to send payload", errno);
        return -1;
    }

    return 0;
}

int ipc_recv_msg(const struct unix_ipc_ctx *ipc_handle, struct ipc_message_pool* msg) {
    if (!ipc_handle || !msg) return -1;

    ssize_t received = recv(ipc_handle->stream_fd, &msg->header, sizeof(struct ipc_message_header), MSG_WAITALL);
    if (received != sizeof(struct ipc_message_header)) {
        HANDLE_ERROR(ipc_handle, "Failed to receive header", errno);
        return -1;
    }   

    if (msg->header.magic != IPC_MAGIC ||
        msg->header.version != ipc_handle->protocol_version ||
        msg->header.payload_len > ipc_handle->max_msg_size) {
        HANDLE_ERROR(ipc_handle, "Invalid message header", EINVAL);
        return -1;
    }

    ((char*)msg->payload)[msg->header.payload_len] = '\0';

    // Receive payload
    received = recv(ipc_handle->stream_fd, msg->payload, msg->header.payload_len, MSG_WAITALL);
    if (received != msg->header.payload_len) {
        HANDLE_ERROR(ipc_handle, "Failed to receive payload", errno);
        free(msg->payload);
        msg->payload = NULL;
        return -1;
    }
   
    // Verify checksum
    uint32_t checksum = calculate_crc32(msg->payload, msg->header.payload_len);
    if (checksum != msg->header.checksum) {
        HANDLE_ERROR(ipc_handle, "Checksum verification failed", EINVAL);
        free(msg->payload);
        msg->payload = NULL;
        return -1;
    }

    return 0;
}

static void error_callback(const char* msg, int err) {
    fprintf(stderr, "Error: %s (errno: %d)\n", msg, err);
}

static void build_proto_msg(struct ipc_message_pool* msg, void *src, uint32_t len)
{
    msg->payload = src;
    msg->header.payload_len = len;
    msg->header.checksum = calculate_crc32(src, len);   
}

static void subs_to_server_event(struct unix_ipc_ctx *ctx, void *storage_msg_pool)
{
    if (!ctx)
        return;

    struct ipc_message_pool recv_msg = {};
    recv_msg.payload = storage_msg_pool;

    struct ipc_message_pool msg_to_send = {
        .header = {
            .magic = IPC_MAGIC,
            .version = 1,
            .type = IPC_MSG_DATA,
        }
    };

    while (!g_need_exit)
    {
        if ((ctx->stream_fd = accept(ctx->fd, 0, 0)) == -1)
            continue;//wait the client to connect
        
        printf("server: client acceppted\n");
        
        while (1) 
        {
            if (ipc_recv_msg(ctx, &recv_msg) != 0)
                break;

            printf("Received: %s\n", (const char*)recv_msg.payload);

            const char *msg = "OK, I Received Your Message";
            build_proto_msg(&msg_to_send, (void*)msg, strlen(msg));
            ipc_send_msg(ctx, &msg_to_send);
        }

        close(ctx->stream_fd);
        printf("server: Client disconnected\n");
    }
    
    ipc_ctx_cleanup(ctx);
   
}

static void subs_to_client_event(struct unix_ipc_ctx *ctx, void *storage_msg_pool)
{
    if (!ctx)
        return;

    struct ipc_message_pool recv_msg = {};
    recv_msg.payload = storage_msg_pool;

    struct ipc_message_pool msg_to_send = {
        .header = {
            .magic = IPC_MAGIC,
            .version = 1,
            .type = IPC_MSG_DATA,
        }
    };
    
    char temp_buffer[1024];
    while (!g_need_exit)
    {        
        if (fgets(temp_buffer, sizeof(temp_buffer), stdin) == NULL)
            break;

        size_t len = strlen(temp_buffer);
        if (len > 1 && temp_buffer[len-1] == '\n')
            temp_buffer[--len] = '\0';
        else
            continue;

        build_proto_msg(&msg_to_send, temp_buffer, len);
        
        if (ipc_send_msg(ctx, &msg_to_send) != 0)
            break;


        if (ipc_recv_msg(ctx, &recv_msg) != 0)
            break;
        
        printf("Server response: %s\n", (const char*)recv_msg.payload);
    }
    
    ipc_ctx_cleanup(ctx);
}

int main(int argc, char **argv)
{
    int daemon_mode = 0;
    int arg_opt = 0;
    
    while((arg_opt = getopt(argc, argv, ":sc")) != -1)  
    {  
        switch(arg_opt)  
        {  
            case 's':
                daemon_mode = 1;
                printf("Run IPC as server\n");
                break;  
            case 'c':  
                daemon_mode = 2;
                printf("Run IPC as client\n");
                break;  
            case ':':
            default:
                printf("Usage ./ipc-x [-c]: client or [-s] : server\n");  
                exit(EXIT_FAILURE);
                break;
        }  
    }  

    _reg_sigaction();
    
    struct ipc_config config = {
        .socket_path = IPC_PATH,
        .max_msg_size = MAX_MSG_SIZE, 
        .protocol_version = IPC_PROTO_VER,
        .error_handler = error_callback
    };
    
    void *msg_pool_buff = calloc(1, MAX_MSG_SIZE);
    if (daemon_mode == 1) {
        struct unix_ipc_ctx *server_ctx = init_ipc_srv_ctx(&config);
        subs_to_server_event(server_ctx, msg_pool_buff);
    } else if (daemon_mode == 2) {
        struct unix_ipc_ctx *client_ctx = init_ipc_client_ctx(&config);
        subs_to_client_event(client_ctx, msg_pool_buff);
    }

    free(msg_pool_buff);
    
    return 0;
}