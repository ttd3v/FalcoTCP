#ifndef NETWORKER_H
#define NETWORKER_H


#include "numbers.h"
#if __tls__
#include <openssl/crypto.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <liburing.h>

// Aliases
typedef uint64_t u64;
typedef uint8_t u8;
typedef size_t usize;

// Client states
enum State {
    #if __tls__
    TlsHandshake = -1,
    #endif
    NonExistent = 0,
    WaitingForAccept = -2,
    Idle = 1,
    HeadersReaden = 2,
    Finished_H = 3,
    Reading = 4,
    Finished_R = 5,
    Available = 6,
    Processing = 7,
    Ready = 8,
    WrittingSock = 9,
    Kill = 10,
    Finished_WS = 11,
    Cooldown = 12,
};

typedef union{
    struct{
        u32 Author;
        int Operation;
        
    };
    u64 value;
} UserDataOpt;

// Message headers
#pragma pack(push, 1)
typedef struct {
    u64 size;
    u8 compr_alg;
} MessageHeaders;
#pragma pack(pop)
// Client structure

typedef struct {
    int sock;
    unsigned char* request;
    unsigned char* response;
    MessageHeaders req_headers; 
    u64 response_size;
    u64 recv_offset;
    u64 writev_offset;
    u64 id; 
    i32 state;
    u64 activity;
    u64 capacity;
    u8 flag;
    #if __tls__
    SSL *ssl;
    unsigned int ktls; // MSB -> RECV TLS enabled | LSB -> KTLS SEND enabled 
    #endif
} Client;

// Compression algorithms
enum CompressionAlgorithm {
    None = 0,
    LZMA = 1,
    GZIP = 2,
    LZ4 = 3,
    ZSTD = 4,
};

// IO operations
enum Operation {
    OP_SocketAcc = 0,
    OP_Read = 1,
    OP_Write = 2,
    OP_Close = 3,
};

// Networker configuration
struct NetworkerSettings {
    char host[16];
    unsigned short port;
    unsigned short max_queue;
    unsigned short max_clients;
    #if __tls__
    char* cert_file;
    char* key_file;
    #endif
};

// Networker main structure
typedef struct {
    int initiated;
    int sock;
    u64 client_num;
    Client* clients;
    struct io_uring *ring;
    #if __tls__
    SSL_CTX *ssl_ctx;
    #endif
} Networker;

// Rust helper struct
typedef struct {
    Client* client;
    usize exists;
} SomeClient;

// Function declarations
int start(Networker* self, struct NetworkerSettings* s);
int proc(Networker* self);
int apply_client_response(Networker* self, u64 client_id, unsigned char* buffer, u64 buffer_size, int compression_algorithm);
SomeClient get_client(Networker* self);
int claim_client(Networker* self, u64 client_id);
int kill_client(Networker* self, u64 client_id);
int cycle(Networker* self);

#endif // NETWORKER_H

