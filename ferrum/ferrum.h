#ifndef __FERRUM_H__

#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include "../external/libs/include/hiredis/hiredis.h"
#include "../log.h"
#include "../ssherr.h"

#define FERRUM_SECURE_SERVER_VERSION "1.0.0"
#define FERRUM_SUCCESS 0

#define ferrum_fill_zero(a, b) memset(a, 0, b)
#define ferrum_cast_to_const_void_ptr(a) (const void *)(a)

#define FERRUM_IP_STRING_LEN 64
#define FERRUM_LOGIN_URL_LEN 512
#define FERRUM_HOST_ID_LEN 32

/**
 * @brief ferrum sockaddr union for ipv4 and ipv6
 *
 */
typedef union ferrum_sockaddr {
    struct sockaddr base;
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
} ferrum_sockaddr_t;

/**
 * @brief ferrum server data holder
 *
 */
typedef struct ferrum {
    // creates a random tunnel id, an alternate to ssh session identifier
    struct {
        char id[64];
    } tunnel;

    struct {
        // connected client ip address holder for ipv4 and ipv6
        char ipaddr[64];
        // connected client port
        int32_t port;
    } client;

    struct {
        // assigned ip address from us
        char ipaddr[64];
        // assigned tunnel
        char tunnel[16];
    } assigned;

    struct {
        char host[32];
        int32_t port;
        redisContext *context;
    } redis;

    struct {
        char url[FERRUM_LOGIN_URL_LEN];
    }login;

    struct {
        char id[FERRUM_HOST_ID_LEN];
    }host;

} ferrum_t;

// inits some field, perhaps connection to redis
int32_t ferrum_create(ferrum_t **ferrum);
int32_t ferrum_destroy(ferrum_t *ferrum);
// fills session_id field with random values as hex
int32_t ferrum_generate_tunnel_id(ferrum_t *ferrum);
// sets ip address
int32_t ferrum_set_client_ip(ferrum_t *ferrum, const char *ip, int port);
// sets assigned_ipaddr
int32_t ferrum_set_assigned_ip(ferrum_t *ferrum, const char *ip);
// sets server side assigned tunnel
int32_t ferrum_set_assigned_tunnel(ferrum_t *ferrum, const char *tunnel);

int32_t ferrum_redis_connect(ferrum_t *ferrum);
int32_t ferrum_redis_disconnect(ferrum_t *ferrum);
int32_t ferrum_redis_test(ferrum_t *ferrum);
int32_t ferrum_redis_subpubtest(ferrum_t *ferrum);

/////////////// UTIL functions ////////////////////////////////////
/**
 * @brief resolves a service name to an ip
 * @example redis:5454
 * @return int32_t
 */
int32_t ferrum_util_resolve(const char *name, ferrum_sockaddr_t *addr,
                            int32_t defaultport);

/**
 * @brief converts @see struct sockaddr to @see ferrum_sockaddr_t
 */
int32_t ferrum_util_addr_to_ferrum_addr(const struct sockaddr *addr,
                                        ferrum_sockaddr_t *sock);

/**
 * @brief converts @see ferrum_sockaddr_t to string like 192.168.10.10 or
 * 192.168.10.10:2626
 *
 * @param sock
 * @param buffer
 * @param port sets port number
 * @param showport shows port in ip string
 * @return int32_t
 */
int32_t ferrum_util_addr_to_ipport_string(const ferrum_sockaddr_t *sock,
                                          char ip[FERRUM_IP_STRING_LEN],
                                          int32_t *port, int showport);

/**
 * @brief converts an ip and port to @see ferrum_sockaddr_t
 *
 * @param ip
 * @param port
 * @param addr
 * @return int32_t
 */
int32_t ferrum_util_ipport_to_addr(const char *ip, int32_t port,
                                   ferrum_sockaddr_t *addr);

/**
 * @brief  converts generic @see struct sockaddr to @see ferrum_sockaddr_t
 *
 * @param addr
 * @param sock
 * @return int32_t
 */
int32_t ferrum_util_addr_to_ferrum_addr(const struct sockaddr *addr,
                                        ferrum_sockaddr_t *sock);

// gets current time UTC in micro seconds
int64_t ferrum_util_micro_time();

// fill with random characters
void ferrum_util_fill_random(char *dest,size_t len);

#endif