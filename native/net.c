#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <bits/types.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <liburing/io_uring.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>   
#include <arpa/inet.h>    
#include <time.h>
#include <unistd.h>       
#include "numbers.h"
#include <liburing.h>
#include "net.h"
#include <netinet/tcp.h>

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
    printf("Server listening on port %d with backlog %d\n", settings.port, settings.max_queue);
    self->sock = sock;
    self->initiated = 1;

    self->clients = (Client*)calloc(self->client_num, sizeof(Client));
    if(!self->clients){
        return -ENOMEM;  
    }
    for(usize i = 0; i < self->client_num; i++){
        self->clients[i].id = i;
        self->clients[i].request = NULL;
        self->clients[i].response = NULL;
        self->clients[i].state = NonExistent;
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
        free(self->author_log);
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
        if(self->clients[i].state != Kill && self->clients[i].state != NonExistent){
            self->clients[i].state = Kill;  
        }
    }
    
    proc(self);
    
    for(u64 i = 0; i < self->client_num; i++){
        #if __tls__
        if (self->clients[i].ssl) {
            SSL_shutdown(self->clients[i].ssl);
            SSL_free(self->clients[i].ssl);
            self->clients[i].ssl = NULL;
        }
        #endif
        
        if(self->clients[i].sock > 0) {
            close(self->clients[i].sock);
        }
        
        sfree(self->clients[i].request);
        sfree(self->clients[i].response);
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

    u64 now = time(NULL);
    
    for(u64 i = 0; i < self->client_num; i++){
        if(self->clients[i].state == NonExistent){
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            io_uring_prep_accept(sqe, self->sock, NULL,NULL, 0);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_SocketAcc;
            self->clients[i].state = WaitingForAccept;
            sqe->user_data = data.value;
            printf("Submitting accept on socket %d for client slot %lu\n", self->sock, i);
            continue;
        }       
        
        if(self->clients[i].state == WaitingForAccept){continue;}

        #if __tls__
        
        if(self->clients[i].state == TlsHandshake){
            if (self->clients[i].ssl == NULL) {
                self->clients[i].ssl = SSL_new(self->ssl_ctx);
                if (self->clients[i].ssl == NULL) {
                    ERR_print_errors_fp(stderr);
                    self->clients[i].state = Kill;
                    continue;
                }
        
                SSL_set_fd(self->clients[i].ssl, self->clients[i].sock);
            }
    
            // Perform SSL handshake
            int handshake_result = SSL_accept(self->clients[i].ssl);
    
            if (handshake_result <= 0) {
                self->clients[i].state = Kill;     
                continue;
            }
    
    
            if (BIO_get_ktls_send(SSL_get_wbio(self->clients[i].ssl)) && BIO_get_ktls_recv(SSL_get_rbio(self->clients[i].ssl))) {
                self->clients[i].ktls = 1;
            } else {
                self->clients[i].state = Kill;
                continue;
            }
            self->clients[i].state = Idle;
            continue; 
        }

        #endif

        if(self->clients[i].state == Idle){
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            if((now-self->clients[i].activity) > 1200){
                self->clients[i].state = Kill; 
                continue;
            }
            data.Operation = OP_Read;
            data.Author = i;
            sqe->user_data = data.value;
            self->clients[i].state = Finished_H;
            io_uring_prep_read(sqe,self->clients[i].sock, (unsigned char*)(&self->clients[i].req_headers)+self->clients[i].recv_offset, MESSAGE_HEADERS_SIZE-self->clients[i].recv_offset, 0);
            continue;
        }

        if(self->clients[i].state == Finished_H){
            if(self->clients[i].recv_offset == MESSAGE_HEADERS_SIZE){
                self->clients[i].recv_offset = 0;
                deserialize_message_headers((const uint8_t*)&self->clients[i].req_headers, 
                            &self->clients[i].req_headers); 
                self->clients[i].state = Reading;
            }else{
                if(self->clients[i].recv_offset == 0){
                    self->clients[i].state = Idle;
                    continue;
                }
                UserDataOpt data = {0};
                struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                data.Author = i;
                data.Operation = OP_Read;
                sqe->user_data = data.value;
                io_uring_prep_read(sqe,self->clients[i].sock, (unsigned char*)(&self->clients[i].req_headers)+self->clients[i].recv_offset, MESSAGE_HEADERS_SIZE-self->clients[i].recv_offset, 0);
                continue;
            }
        }

        if(self->clients[i].state == Reading){
            self->clients[i].capacity = self->clients[i].request==NULL?0:self->clients[i].capacity;
            if(self->clients[i].capacity < self->clients[i].req_headers.size || self->clients[i].request == NULL){
                sfree(self->clients[i].request);
                self->clients[i].request = malloc(self->clients[i].req_headers.size);
                self->clients[i].capacity = self->clients[i].req_headers.size;
            }
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_Read;
            sqe->user_data = data.value;
            self->clients[i].state = Finished_R;
            io_uring_prep_read(sqe,self->clients[i].sock,self->clients[i].request + self->clients[i].recv_offset,self->clients[i].req_headers.size-self->clients[i].recv_offset,0);
            continue;
        }

        if(self->clients[i].state == Finished_R){
            if(self->clients[i].recv_offset == self->clients[i].req_headers.size){
                self->clients[i].recv_offset = 0;
                self->clients[i].state = Available;
            }else{
                self->clients[i].state = Reading;
            }
            continue;
        }

        if(self->clients[i].state == Ready){
            self->clients[i].writev_offset = 0;
            self->clients[i].activity = now;
            self->clients[i].state = WrittingSock;
            continue;
        }
        if(self->clients[i].state == WrittingSock){
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_Write;
            sqe->user_data = data.value;
            io_uring_prep_write(sqe, self->clients[i].sock, 
                       (self->clients[i].response) + self->clients[i].writev_offset, 
                       self->clients[i].response_size - self->clients[i].writev_offset, 0);
            self->clients[i].state = Finished_WS;
            continue;
        }
        if(self->clients[i].state == Finished_WS){
            if(self->clients[i].writev_offset >= self->clients[i].response_size){
                self->clients[i].writev_offset = 0;
                self->clients[i].response_size = 0;
                self->clients[i].state = Idle;
                sfree(self->clients[i].response); 
                self->clients[i].response = NULL;
                sfree(self->clients[i].request); 
                self->clients[i].request = NULL;
            }else{
                self->clients[i].state = WrittingSock;
            }
            continue;
        }
        if(self->clients[i].state == Kill){
            #if __tls__
            if (self->clients[i].ssl) {
                SSL_shutdown(self->clients[i].ssl);
                SSL_free(self->clients[i].ssl);
                self->clients[i].ssl = NULL;
                self->clients[i].ktls = 0;
            }
            #endif
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            UserDataOpt data = {0};
            data.Author = i;
            data.Operation = OP_Close;
            sqe->user_data = data.value;

            io_uring_prep_close(sqe, self->clients[i].sock);
            self->clients[i].state = NonExistent;
            self->clients[i].recv_offset = 0;
            self->clients[i].writev_offset = 0;
            self->clients[i].capacity = 0;
            self->clients[i].response_size = 0;
            sfree(self->clients[i].response);
            sfree(self->clients[i].request);
            memset(&self->clients[i].req_headers, 0, sizeof(MessageHeaders));
            continue;
        }
    }
    {
        int res = io_uring_submit(&ring);
        printf("Submitted %d operations\n", res);
        if (res < 0){
            return res;
        };
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

        
        
        switch((int)data.Operation){
            case OP_Read:
                self->clients[ptr].activity = now;
                self->clients[ptr].recv_offset += res;
                break;
            case OP_Write:
                self->clients[ptr].writev_offset += res;
                self->clients[ptr].activity = now;
                break;
            case OP_SocketAcc:
                {
                u64 saved_id = self->clients[ptr].id;
                memset(&self->clients[ptr], 0, sizeof(Client));
                self->clients[ptr].sock = res;
                int flag = 1;
                if (setsockopt(self->clients[ptr].sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0){
                    printf("Failed to setsocketopt, killing.\n");
                    self->clients[ptr].state = Kill;
                    break;;
                };
                if (fcntl(self->clients[ptr].sock, F_SETFL, O_NONBLOCK) < 0){
                    self->clients[ptr].state = Kill;
                    printf("Failed to set nonblock (fcntl), killing.\n");
                    break;
                };

                #if __tls__
                    self->clients[ptr].state = TlsHandshake;    
                #else
                    self->clients[ptr].state = Idle;
                #endif
                self->clients[ptr].activity = now;
                self->clients[ptr].id = saved_id;
                
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
        if(self->clients[i].state == Available){
            return (SomeClient) {&self->clients[i],1};
        }
    }
    return (SomeClient){NULL, 0};
}

int claim_client(Networker* self, u64 client_id){
    if(client_id < self->client_num && self->clients[client_id].state == Available){
        self->clients[client_id].state = Processing;
        return 0;
    }
    return -ENOPKG;
}
int kill_client(Networker* self, u64 client_id){
    if(client_id < self->client_num){
        self->clients[client_id].state = Kill;
        return 0;
    }
    return -ENOPKG;
}

int cycle(Networker* self){
    if (self->initiated != 1) return -1;
    return proc(self);  
}
