#ifndef IPC_PROTO
#define IPC_PROTO

#include <stdint.h>

/*IPC Configuration*/
#define IPC_MAGIC 0x4950434D  
#define IPC_MAX_EVENTS 10
#define IPC_PROTO_VER 1
#define IPC_PATH "/tmp/.unix_ipc"
#define MAX_MSG_SIZE 4096

#define HANDLE_ERROR(ctx, msg, err) do { \
    if ((ctx)->error_handler) { \
        (ctx)->error_handler((msg), (err)); \
    } \
} while(0)

enum MSG_TYPE
{
    IPC_MSG_DATA    = 0x01,
    IPC_MSG_CONTROL = 0x02,
    IPC_MSG_ERROR   = 0x04,
    IPC_MSG_CLOSE   = 0x08
};

struct __attribute__((packed)) ipc_message_header {
    __uint32_t magic;         // Magic number for validation
    __uint16_t version;       // Protocol version
    __uint16_t type;          // Message type
    __uint32_t payload_len;   // Length of payload
    __uint32_t checksum;      // CRC32 of payload
};

// Message structure
struct ipc_message_pool {
    struct ipc_message_header header;
    void* payload;
};

// Configuration structure
struct ipc_config {
    const char* socket_path;
    uint32_t max_msg_size;
    uint16_t protocol_version;
    void (*error_handler)(const char*, int);
};

struct unix_ipc_ctx {
    int fd;                    
    int stream_fd;
    uint32_t max_msg_size;    
    uint16_t protocol_version; 
    uint8_t is_server;
    void (*error_handler)(const char*, int);
};

#endif