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
#include <unistd.h>
#include "net.h"

#if TLS
#include "openssl/ssl.h"
#include <openssl/crypto.h>
#endif

typedef u64 number;

#if !BLOCKING
#include <string.h>
#include <fcntl.h>
#endif

// 500 MiB
#define MAX_PAYLOAD_SIZE 524288000

// pc stands for Primitive Client

#if !BLOCKING
enum PCASYNC{
    PCASYNC_Nothing = 0,
    PCASYNC_InputHeaders = 1,
    PCASYNC_InputPayload = 2,
    PCASYNC_OutputHeaders = 3,
    PCASYNC_OutputPayload = 4,
    PCASYNC_Done = 5,
};
#endif
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
    #if !BLOCKING
    unsigned char *input;
    unsigned char *output;
    MessageHeaders headers[2];
    u64 readen;
    u64 writen;
    PcAsync processing;
    u64 timeout_micro_secs;
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
        return -ENONET; 
    }
    PrimitiveClient s={0};
    *self=s;
    #if !BLOCKING
    self->output = NULL;
    self->timeout_micro_secs = 1000000;
    #endif
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

    #if !BLOCKING
        int flags= fcntl(fd, F_GETFL,0);
        if(flags < 0){
            return -1;
        }
        flags |= O_NONBLOCK;
        result = fcntl(fd, F_SETFL, flags);
        if(result < 0){
            return -ENOTSOCK;
        };
    #endif
    self->fd = fd;
    return 0;
}



void pc_set_timeout(PrimitiveClient *self, u64 micro_secs){
    #if BLOCKING
    struct timeval tv = {0};
    tv.tv_sec = micro_secs / 1000000;
    tv.tv_usec = micro_secs % 1000000;
    setsockopt(self->fd, SOL_SOCKET, SO_RCVTIMEO, (const unsigned char*)&tv, sizeof(tv));
    setsockopt(self->fd, SOL_SOCKET, SO_SNDTIMEO, (const unsigned char*)&tv, sizeof(tv));
    #else
        self->timeout_micro_secs = micro_secs;
    #endif
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


#if !BLOCKING
int pc_async_step(PrimitiveClient *self){
    int res = 0;
    if(self->processing == PCASYNC_Nothing){
        return res;
    }
    switch(self->processing){
        case PCASYNC_InputHeaders:
            {
                // Serializing at every PCASYNC_InputHeaders because its very unlikely for it to require two passes
                // The cost of holding a buffer is higher than serialize more than once
                // The likelihood of it needing more than 2 passes is very low.
                unsigned char buffer[sizeof(MessageHeaders)];
                serialize_message_headers(&self->headers[0], buffer);
                int result = pc_write(self, buffer+self->writen, sizeof(MessageHeaders)-self->writen);
                res = result & -(result < 0);
                self->writen += result;
                // These ternary operations may be turned into a single instruction, easy to branch-predict otherwise.
                self->processing = self->writen==sizeof(MessageHeaders)?PCASYNC_InputPayload:PCASYNC_InputHeaders;
                self->writen = self->writen==sizeof(MessageHeaders)?0:self->writen;
                break;
            }
        case PCASYNC_InputPayload:
            {
                int result = pc_write(self, self->input+self->writen, self->headers[0].size-self->writen);
                res = result & -(result < 0);
                self->writen += result;
                self->processing = self->writen==self->headers[0].size?PCASYNC_OutputHeaders:PCASYNC_InputPayload;
                self->writen = self->writen==self->headers[0].size?0:self->writen;
                break; 
            }
        case PCASYNC_OutputHeaders:
            {
                int result = pc_read(self, ((unsigned char*)&self->headers[1]+self->readen), sizeof(MessageHeaders)-self->readen);
                res = result & -(result < 0);
                self->readen += result;
                // These ternary operations may be turned into a single instruction, easy to branch-predict otherwise.
                self->processing = self->readen==sizeof(MessageHeaders)?PCASYNC_OutputPayload:PCASYNC_OutputHeaders;
                if(self->readen == sizeof(MessageHeaders)){
                    unsigned char buffer[sizeof(MessageHeaders)];
                    memcpy(buffer, &self->headers[1], sizeof(MessageHeaders));
                    self->readen = 0;
                    deserialize_message_headers(buffer,&self->headers[1]);
                    sfree(self->output); // Always: NULL or a valid pointer
                    if(self->headers[1].size > MAX_PAYLOAD_SIZE){
                        res=-ENOMEM;
                        break;
                    }
                    self->output = malloc(self->headers[1].size);
                    res = !self->output?-ENOMEM:0;
                    self->output = res < 0?NULL:self->output;
                }
                break; 
            }
        case PCASYNC_OutputPayload:
            {
                int result = pc_read(self, self->output+self->readen, self->headers[1].size-self->readen);
                res = result & -(result < 0);
                self->readen += result; 
                self->processing = self->readen==self->headers[1].size?PCASYNC_Done:PCASYNC_OutputPayload;
                self->readen = self->readen==self->headers[1].size?0:self->readen;
                break;
            }
        default: break;
    }
    self->writen = res>=0?self->writen:0;
    self->readen = res>=0?self->readen:0;
    self->processing = res>=0?self->processing:0;
    return res;
};
int pc_async_input(PrimitiveClient *self,MessageHeaders headers, unsigned char* buffer){
    self->headers[0] = headers;
    self->input = buffer;
    self->writen = 0;
    self->readen = 0;
    sfree(self->output);
    self->processing = PCASYNC_InputHeaders; 
    return pc_async_step(self);
}
int pc_async_output(PrimitiveClient *self, MessageHeaders *restrict headers, unsigned char* buffer){
    // Even while it is in fact not the most performant, I will be reallocating the memory into another buffer, and cloning it for FFI (With rust or another). That is for safety since I can't predict accuratelly the behavior of memory since it goes to other hands.
    if(self->processing != PCASYNC_Done){
        return -ENOPKG;
    }
    buffer = malloc(self->headers[1].size);
    if(!buffer){
        return -ENOMEM;
    }
    memcpy(buffer, self->output, self->headers[1].size);
    memcpy(headers, &self->headers[1], sizeof(MessageHeaders));
    sfree(self->output);
    sfree(self->input);
    return 0;
}
#endif

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
            res = result & -(result < 0);
            written += result;
        }
    }
    if(res < 0){
        printf("bad -\n");
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
    {
        unsigned char buffer[sizeof(MessageHeaders)] = {0};
        while(readen < sizeof(MessageHeaders) && res >= 0){
            int result = pc_read(self, (buffer+readen), sizeof(MessageHeaders)-readen);
            res = result & -(result < 0);
            readen += result;
        }
        deserialize_message_headers(buffer, headers);
    }
    {
        readen = 0;
        u64 size = headers->size;
        *buf = malloc(size);
        res = (!*buf)?-ENOMEM:0; 
        if(res < 0){
            return res;
        }
        while(readen < size && res >= 0){
            int result = pc_read(self,(*buf+readen), size-readen);
            res = result & -(result < 0);
            if(res < 0){return res;}
            readen += result;
            
        }
    }
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
