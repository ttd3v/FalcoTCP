#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <bits/types.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <liburing/io_uring.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>   
#include <arpa/inet.h>    
#include <threads.h>
#include <time.h>
#include <unistd.h>       
#include "numbers.h"
#include <liburing.h>
#include "net.h"
#include <netinet/tcp.h>


#define iclnt self->clients[i]
#if __tls__
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define sfree(p) do { free(p); (p) = NULL; } while(0)
#define MESSAGE_HEADERS_SIZE 9






// Serialize into a buffer (little-endian)
static inline void serialize_message_headers(const MessageHeaders *msg, uint8_t *buf) {
    // store size in little-endian
    for (int i = 0; i < 8; i++) {
        buf[i] = (msg->size >> (i * 8)) & 0xFF;
    }
    buf[8] = msg->compr_alg;  // 1 byte
}

// Deserialize from a buffer (little-endian)
static inline void deserialize_message_headers(const uint8_t *buf, MessageHeaders *msg) {
    msg->size = 0;
    for (int i = 0; i < 8; i++) {
        msg->size |= ((uint64_t)buf[i]) << (i * 8);
    }
    msg->compr_alg = buf[8];
}
#if __tls__
int tls_setup(Networker* self, const char* cert_file, const char* key_file) {
    
    self->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (self->ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!SSL_CTX_set_min_proto_version(self->ssl_ctx, TLS1_2_VERSION)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(self->ssl_ctx);
        return -1;
    }

    long opts = SSL_OP_IGNORE_UNEXPECTED_EOF | 
                SSL_OP_NO_RENEGOTIATION | 
                SSL_OP_CIPHER_SERVER_PREFERENCE |
                SSL_OP_ENABLE_KTLS;
    SSL_CTX_set_options(self->ssl_ctx, opts);

    if (SSL_CTX_use_certificate_chain_file(self->ssl_ctx, cert_file) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(self->ssl_ctx);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(self->ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(self->ssl_ctx);
        return -1;
    }

    SSL_CTX_set_min_proto_version(self->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(self->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(self->ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");

    unsigned char cache_id[] = "cache";
    SSL_CTX_set_session_id_context(self->ssl_ctx, cache_id, sizeof(cache_id));
    SSL_CTX_set_session_cache_mode(self->ssl_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(self->ssl_ctx, 1024);
    SSL_CTX_set_timeout(self->ssl_ctx, 3600);

    SSL_CTX_set_verify(self->ssl_ctx, SSL_VERIFY_NONE, NULL);

    return 0;
}
#endif

int start(Networker* self, struct NetworkerSettings* s){
    struct NetworkerSettings settings = *s;
    if (self->initiated > 0){
        return 0;
    }

    memset(self, 0, sizeof(Networker));

    self->client_num = s->max_clients;
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0){
        return -errno;
    }
    
    struct  sockaddr_in sockad = {0};
    sockad.sin_family = AF_INET;
    sockad.sin_port = htons(settings.port);
    if (inet_pton(AF_INET, settings.host, &sockad.sin_addr) <= 0) {
        close(sock);
        return -errno;
    }

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        close(sock);
        return -errno;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        close(sock);
        return -errno;
    }

    int _l = bind(sock, (struct sockaddr*)&sockad, sizeof(sockad));
    if (_l < 0){
        close(sock);
        return -errno;
    }
    

    int _l1 = listen(sock, settings.max_queue);
    if (_l1 < 0){
        close(sock);
        return -errno;
    }
    self->sock = sock;
    self->initiated = 1;

    self->clients = (Client*)malloc(self->client_num*sizeof(Client));
    if(!self->clients){
        return -ENOMEM;  
    }
    memset(self->clients, 0, sizeof(Client)*self->client_num);
    for(usize i = 0; i < self->client_num; i++){
        iclnt.id = i;
        iclnt.capacity = 0;
        iclnt.request = NULL;
        iclnt.response = NULL;
        iclnt.state = NonExistent;
        iclnt.flag = 0;
    }

    self->ring = calloc(1,sizeof(struct io_uring));
    if (!self->ring){
        free(self->clients);
        close(sock);
        return -ENOMEM;
    }
    {
        int res = io_uring_queue_init(self->client_num>0?self->client_num:1, self->ring, 0);
        if(res < 0) {
            free(self->clients);
            free(self->ring);
            close(sock);
            return res;
        }
    }
    #if __tls__
    if (tls_setup(self, s->cert_file, s->key_file) < 0) {
        free(self->clients);
        free(self->ring);
        close(sock);
        return -1;
    }
    #endif


    return 0;
}

void networker_drop(Networker *self){
    if (!self || self->initiated != 1) {
        return;
    }
    
    for(u64 i = 0; i < self->client_num; i++){
        if(iclnt.state != Kill && iclnt.state != NonExistent){
            iclnt.state = Kill;  
        }
    }
    
    proc(self);
    
    for(u64 i = 0; i < self->client_num; i++){
        #if __tls__
        if (iclnt.ssl) {
            SSL_shutdown(iclnt.ssl);
            SSL_free(iclnt.ssl);
            iclnt.ssl = NULL;
        }
        #endif
        
        if(iclnt.sock > 0) {
            close(iclnt.sock);
        }
        
        sfree(iclnt.request);
        sfree(iclnt.response);
    }
    
    free(self->clients);
    self->clients = NULL;
    
    if (self->ring) {
        io_uring_queue_exit(self->ring);
        free(self->ring);
        self->ring = NULL;
    }
    
    #if __tls__
    if (self->ssl_ctx) {
        SSL_CTX_free(self->ssl_ctx);
        self->ssl_ctx = NULL;
    }
    #endif
    
    if(self->sock > 0) {
        close(self->sock);
        self->sock = -1;
    }
    
    self->initiated = 0;
}
int proc(Networker* self){
    #define ring *self->ring
    #define DRAIN()\
        do{\
            iclnt.flag |= 1;\
        }while(0);\

    #define mutate ;mut++;DRAIN();
    u64 now = time(NULL);
    int mut = 0; 
    for(u64 i = 0; i < self->client_num; i++){
        if((iclnt.flag & 1)==1){continue;}
        //printf("[SERVER] Client(%lu) : %i\n",i,iclnt.state);
        if(iclnt.state == NonExistent){
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            io_uring_prep_accept(sqe, self->sock, NULL,NULL, 0);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_SocketAcc;
            iclnt.state = WaitingForAccept;
            sqe->user_data = data.value;
            mutate
            continue;
        }       
        
        if(iclnt.state == WaitingForAccept){continue;}

        #if __tls__
        
        if(iclnt.state == TlsHandshake){
            if (iclnt.ssl == NULL) {
                iclnt.ssl = SSL_new(self->ssl_ctx);
                if (iclnt.ssl == NULL) {
                    ERR_print_errors_fp(stderr);
                    iclnt.state = Kill;
                    continue;
                }
        
                SSL_set_fd(iclnt.ssl, iclnt.sock);
            }
    
            // Perform SSL handshake
            int handshake_result = SSL_accept(iclnt.ssl);
    
            if (handshake_result <= 0) {
                iclnt.state = Kill;     
                continue;
            }
    
    
            if (BIO_get_ktls_send(SSL_get_wbio(iclnt.ssl)) && BIO_get_ktls_recv(SSL_get_rbio(iclnt.ssl))) {
                iclnt.ktls = 1;
            } else {
                iclnt.state = Kill;
                continue;
            }
            iclnt.state = Idle;
            continue; 
        }

        #endif

        if(iclnt.state == Idle){
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            if((now-iclnt.activity) > 1200){
                iclnt.state = Kill; 
                continue;
            }
            data.Operation = OP_Read;
            data.Author = i;
            iclnt.state = Finished_H;
            sqe->user_data = data.value;
            mutate
            io_uring_prep_read(sqe,iclnt.sock, (unsigned char*)(&iclnt.req_headers)+iclnt.recv_offset, MESSAGE_HEADERS_SIZE-iclnt.recv_offset, 0);
            continue;
        }

        if(iclnt.state == Finished_H){
            if(iclnt.recv_offset == MESSAGE_HEADERS_SIZE){
                iclnt.recv_offset = 0;
                unsigned char buffer[9];
                memcpy(buffer, &iclnt.req_headers, 9);
                deserialize_message_headers(buffer, &iclnt.req_headers);
                iclnt.state = Reading;
                //printf("[SERVER] Client(%lu) Headers->size %lu\n",i,iclnt.req_headers.size);
            }else{
                if(iclnt.recv_offset == 0){
                    iclnt.state = Idle;
                    continue;
                }
                UserDataOpt data = {0};
                struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                data.Author = i;
                data.Operation = OP_Read;
                sqe->user_data = data.value;
                mutate
                io_uring_prep_read(sqe,iclnt.sock, (unsigned char*)(&iclnt.req_headers)+iclnt.recv_offset, MESSAGE_HEADERS_SIZE-iclnt.recv_offset, 0);
                continue;
            }
        }

        if(iclnt.state == Reading){
            iclnt.capacity = iclnt.request==NULL?0:iclnt.capacity;
            if(iclnt.capacity < iclnt.req_headers.size || iclnt.request == NULL){
                sfree(iclnt.request);
                iclnt.request = malloc(iclnt.req_headers.size);
                iclnt.capacity = iclnt.req_headers.size;
            }
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_Read;
            sqe->user_data = data.value;
            iclnt.state = Finished_R;
            mutate
            io_uring_prep_read(sqe,iclnt.sock,iclnt.request + iclnt.recv_offset,iclnt.req_headers.size-iclnt.recv_offset,0);
            continue;
        }

        if(iclnt.state == Finished_R){
            if(iclnt.recv_offset == iclnt.req_headers.size){
                iclnt.recv_offset = 0;
                iclnt.state = Available;
            }else{
                iclnt.state = Reading;
            }
            continue;
        }

        if(iclnt.state == Ready){
            iclnt.writev_offset = 0;
            iclnt.activity = now;
            iclnt.state = WrittingSock;
            continue;
        }
        if(iclnt.state == WrittingSock){
            mutate
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_Write;
            sqe->user_data = data.value;
            io_uring_prep_write(sqe, iclnt.sock, 
                       (iclnt.response) + iclnt.writev_offset, 
                       iclnt.response_size - iclnt.writev_offset, 0);
            iclnt.state = Finished_WS;
            continue;
        }
        if(iclnt.state == Finished_WS){
            if(iclnt.writev_offset >= iclnt.response_size){
                iclnt.writev_offset = 0;
                iclnt.recv_offset = 0;
                iclnt.response_size = 0;
                iclnt.state = Cooldown;
            }else{
                iclnt.state = WrittingSock;
            }
            continue;
        }
        if(iclnt.state == Kill){
            #if __tls__
            if (iclnt.ssl) {
                SSL_shutdown(iclnt.ssl);
                SSL_free(iclnt.ssl);
                iclnt.ssl = NULL;
                iclnt.ktls = 0;
            }
            #endif
            mutate
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_Close;
            sqe->user_data = data.value;

            io_uring_prep_close(sqe, iclnt.sock);
            iclnt.state = NonExistent;
            iclnt.recv_offset = 0;
            iclnt.writev_offset = 0;
            iclnt.capacity = 0;
            iclnt.response_size = 0;
            sfree(iclnt.response);
            sfree(iclnt.request);
            memset(&iclnt.req_headers, 0, sizeof(MessageHeaders));
            continue;
        }
        if(iclnt.state == Cooldown){
            iclnt.state = Idle;
            sfree(iclnt.response); 
            sfree(iclnt.request);
            iclnt.response = NULL;
            iclnt.request = NULL;
            memset(&iclnt.req_headers, 0, sizeof(MessageHeaders));
            continue;
        }
    }

        
    if(mut != 0){
        int res = io_uring_submit(&ring);
        if (res < 0){
            return res;
        };
    }else{
        thrd_yield();
    }

    while(1){
        struct io_uring_cqe *cqe;
        int ret = io_uring_peek_cqe(&ring, &cqe);
        if (ret == -EAGAIN || ret < 0) break;
        __S32_TYPE res = cqe->res;
        UserDataOpt data = {0};
        data.value = cqe->user_data;
        int ptr = data.Author;
        io_uring_cqe_seen(&ring, cqe);
        if(res < 0){
            self->clients[ptr].state = Kill;
            continue;
        }

        self->clients[ptr].flag &= ~1; 
        self->clients[ptr].activity = now; 
        switch((int)data.Operation){
            case OP_Read:
                self->clients[ptr].recv_offset += res;
                break;
            case OP_Write:
                self->clients[ptr].writev_offset += res;
                break;
            case OP_SocketAcc:
                {
                self->clients[ptr].sock = res;

                #if __tls__
                    self->clients[ptr].state = TlsHandshake;    
                #else
                    self->clients[ptr].state = Idle;
                #endif
                }
                break;
            default: break;
        }
    }
    return 0;
}


//  RUST TOOLS 


int apply_client_response(Networker* self, u64 client_id, unsigned char* buffer, u64 buffer_size, int compression_algorithm){
    if (!(client_id < self->client_num && self->clients[client_id].state == Processing)){
        return -ENOPKG;
    }
    MessageHeaders headers = {0};
    headers.size =  buffer_size;
    headers.compr_alg = compression_algorithm;
    usize rbs = sizeof(MessageHeaders) + buffer_size;
    unsigned char* response_buffer = malloc(rbs);
    if(!response_buffer){
        return -ENOMEM;
    }
    serialize_message_headers(&headers, response_buffer);
    memcpy(response_buffer+MESSAGE_HEADERS_SIZE, buffer, buffer_size);
    self->clients[client_id].response = response_buffer;
    self->clients[client_id].response_size = rbs;
    self->clients[client_id].state = Ready;
    return 0;
}
SomeClient get_client(Networker* self){
    for(usize i = 0; i < self->client_num; i ++) {
        if(iclnt.state == Available){
            return (SomeClient) {&iclnt,1};
        }
    }
    return (SomeClient){NULL, 0};
}

int claim_client(Networker* self, u64 client_id){
    if(client_id < self->client_num && self->clients[client_id].state == Available){
        self->clients[client_id].state = Processing;
        return 0;
    }
    return -ENOKEY;
}
int kill_client(Networker* self, u64 client_id){
    if(client_id < self->client_num){
        self->clients[client_id].state = Kill;
        return 0;
    }
    return -ENOKEY;
}

int cycle(Networker* self){
    if (self->initiated != 1){printf("You have initialize the networker before starting with cycles.\n");return -1;};
    return proc(self);  
}
