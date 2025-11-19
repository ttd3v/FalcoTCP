#include <asm-generic/errno-base.h>
#include <sched.h>
#include <string.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <bits/types/struct_timeval.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <threads.h>
#include <unistd.h>
#include "net.h"

#define loop while(1)
#define BLOCKING 1 
#if TLS
#include "openssl/ssl.h"
#include <openssl/crypto.h>
#endif

typedef u64 number;



// 500 MiB
#define MAX_PAYLOAD_SIZE 524288000

// pc stands for Primitive Client

#define sfree(p) \
    do { \
        if ((p) != NULL) { \
            free(p); \
            (p) = NULL; \
        } \
    } while (0)

typedef int PcAsync;

typedef struct {
    int fd;
    #if TLS
    SSL* ssl;
    SSL_CTX* ctx;
    #endif
} PrimitiveClient;

typedef struct {
    char* host;
    u_int16_t port;
    #if TLS
        char* domain;
    #endif
} PrimitiveClientSettings;

struct Packet{
    MessageHeaders headers;
    unsigned char* value;
};

int pc_create(PrimitiveClient* self, PrimitiveClientSettings *settings_ptr){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    PrimitiveClientSettings settings = *settings_ptr;
    if(fd == -1){
        return -errno; 
    }
    PrimitiveClient s={0};
    *self=s;
    struct sockaddr_in sets = {0};
    sets.sin_family = AF_INET;
    sets.sin_port = htons(settings.port);
    int result = inet_pton(AF_INET, settings.host, &sets.sin_addr);
    if (result < 0){
        close(fd);
        return -errno;
    };
    result = connect(fd, (struct sockaddr*)(&sets), sizeof(sets));
    if(result < 0){
        // exception 2
        close(fd);
        return -errno;
    }
    
    #if TLS
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (self->ssl_ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
        self->ssl = SSL_new(ctx);
        self->ctx = ctx;
        SSL_set_fd(self->ssl, fd);
        SSL_set_tlsext_host_name(self->ssl, settings.domain);
        if (SSL_connect(self->ssl) <= 0) {
            return -1;
        }
    #endif
    self->fd = fd;
    return 0;
}



void pc_set_timeout(PrimitiveClient *self, u64 micro_secs){
    /*struct timeval tv = {0};
    tv.tv_sec = micro_secs / 1000000;
    tv.tv_usec = micro_secs % 1000000;
    setsockopt(self->fd, SOL_SOCKET, SO_RCVTIMEO, (const unsigned char*)&tv, sizeof(tv));
    setsockopt(self->fd, SOL_SOCKET, SO_SNDTIMEO, (const unsigned char*)&tv, sizeof(tv));
    */
    
}


static inline void serialize_message_headers(const MessageHeaders *msg, uint8_t *buf) {
    for (number i = 0; i < 8; i++) {
        buf[i] = (msg->size >> (i * 8)) & 0xFF;
    }
    buf[8] = msg->compr_alg;  
}

static inline void deserialize_message_headers(const uint8_t *buf, MessageHeaders *msg) {
    msg->size = 0;
    for (number i = 0; i < 8; i++) {
        msg->size |= ((uint64_t)buf[i]) << (i * 8);
    }
    msg->compr_alg = buf[8];
}

static inline int pc_write(PrimitiveClient *self, unsigned char *restrict buf, u64 size){
    #if TLS
        return SSL_write(self->ssl, buf, size);
    #else
        return write(self->fd, buf, size);  
    #endif
}


static inline int pc_read(PrimitiveClient *self, unsigned char *restrict buf, u64 size){
    #if TLS
        return SSL_read(self->ssl, buf, size);
    #else
        return read(self->fd, buf, size);  
    #endif
}


#if BLOCKING
int pc_input_request(PrimitiveClient *self, unsigned char *restrict buf, MessageHeaders headers){
    u64 written = 0;
    int res = 0;
    u64 size = headers.size;
    {
        unsigned char hbuf[9];
        memset(hbuf, 0, sizeof(hbuf));
        serialize_message_headers(&headers, hbuf);
        while (written != sizeof(MessageHeaders) && res >= 0){
            int result = pc_write(self, (hbuf)+written, sizeof(headers)-written);     
            written += result;
            if(result < 0){
                switch(result){
                    case EAGAIN:
                        break;
                    default:
                        return -errno;
                }
                sched_yield();
            }
        }
    }
    if(res < 0){
        //printf("bad -\n");
        return -errno;
    }
    written = 0;
    while(written != size && res >= 0){
        int result = pc_write(self,buf+written,size-written);
        res = result & -(result < 0);
        written += result;
    }
    if(res < 0){
        return -errno;
    }
    return 0;
}
#endif

#if BLOCKING
int pc_output_request(PrimitiveClient *self, unsigned char **restrict buf, MessageHeaders *restrict headers){
    u64 readen = 0;
    int res = 0;
    //printf("@\n");
    {
        unsigned char buffer[sizeof(MessageHeaders)] = {0};
        loop{
            int result = pc_read(self, (buffer+readen), sizeof(MessageHeaders)-readen);
            if(result  <= 0){
                if(result == 0){
                    return -EPIPE;
                }
                if(errno == EAGAIN || errno == EWOULDBLOCK){
                    sched_yield();
                    continue;
                }
                return -errno;
            }
            readen += (u64)result;
            if(readen == sizeof(MessageHeaders)){
                break;
            }
        }
        deserialize_message_headers(buffer, headers);
    }
    //printf("@\n");
    {
        readen = 0;
        u64 size = headers->size;
        *buf = malloc(size);
        res = (!*buf)?-ENOMEM:0; 
        if(res < 0){
            return res;
        }
        loop{
            int result = pc_read(self,(*buf+readen), size-readen);
            readen += (u64)result;
            if(result <= 0){return -errno;}
            if(readen == size){break;};
        }
    }
    //printf("@/\n");
    
    return res;
}
#endif

void pc_clean(PrimitiveClient* self){
    close(self->fd);
    #if TLS
    SSL_shutdown(self->ssl);
    SSL_free(self->ssl);
    SSL_CTX_free(self->ctx);
    EVP_cleanup();
    #endif
    #if !BLOCKING
    sfree(self->input);
    sfree(self->output);
    #endif
}
