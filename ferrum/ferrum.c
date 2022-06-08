#include "ferrum.h"

static int32_t srand_initted = 0;
static const char *charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

int64_t ferrum_util_micro_time() {
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return currentTime.tv_sec * (int64_t)1e6 + currentTime.tv_usec;
}

int32_t ferrum_util_addr_to_ferrum_addr(const struct sockaddr *addr,
                                        ferrum_sockaddr_t *sock) {
    if (addr->sa_family == AF_INET) {
        memcpy(&sock->v4, addr, sizeof(struct sockaddr_in));
    }
    if (addr->sa_family == AF_INET6) {
        memcpy(&sock->v6, addr, sizeof(struct sockaddr_in6));
    }
    return FERRUM_SUCCESS;
}
int32_t ferrum_util_ipport_to_addr(const char *ip, int32_t port,
                                   ferrum_sockaddr_t *addr) {
    int32_t result = inet_pton(AF_INET6, ip, &addr->v6.sin6_addr);
    if (result) {
        addr->base.sa_family = AF_INET6;
        addr->v6.sin6_port = htons(port);
        return FERRUM_SUCCESS;
    }
    result = inet_pton(AF_INET, ip, &addr->v4.sin_addr);
    if (result) {
        addr->base.sa_family = AF_INET;
        addr->v4.sin_port = htons(port);
        return FERRUM_SUCCESS;
    }

    return SSH_ERR_INTERNAL_ERROR;
}

int32_t ferrum_util_addr_to_ipport_string(const ferrum_sockaddr_t *sock,
                                          char ip[FERRUM_IP_STRING_LEN],
                                          int32_t *port, int showport) {
    const char *ptr = inet_ntop(
        sock->base.sa_family,
        sock->base.sa_family == AF_INET
            ? ferrum_cast_to_const_void_ptr(&sock->v4.sin_addr)
            : ferrum_cast_to_const_void_ptr(&sock->v6.sin6_addr),
        ip,
        sock->base.sa_family == AF_INET ? sizeof(sock->v4) : sizeof(sock->v6));
    *port = sock->base.sa_family == AF_INET ? ntohs(sock->v4.sin_port)
                                            : ntohs(sock->v6.sin6_port);
    if (ptr && showport) {
        char tmp[FERRUM_IP_STRING_LEN];
        snprintf(tmp, FERRUM_IP_STRING_LEN - 1, "%s#%d", ip, *port);
        strcpy(ip, tmp);  // no problem about copy,
    }

    return ptr ? FERRUM_SUCCESS : SSH_ERR_INTERNAL_ERROR;
}

int32_t ferrum_util_resolve(const char *name, ferrum_sockaddr_t *addr,
                            int32_t defaultport) {
    if (!name || !addr) return SSH_ERR_INVALID_ARGUMENT;
    ferrum_sockaddr_t *addrlist;
    size_t addrlist_len;
    ferrum_fill_zero(addr, sizeof(ferrum_sockaddr_t));
    char *cloned = strdup(name);
    char *ptr = strtok(cloned, "#");
    int32_t port = 0;
    int32_t counter = 0;
    // extra safe
    if (!ptr) {
        ptr = "localhost";
        ptr = strtok(ptr, "#");
    }
    while (ptr) {
        counter++;
        if (counter == 1) {
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;  // : AF_INET6;
            hints.ai_flags |= AI_CANONNAME;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            struct addrinfo *result, *tmp;
            int res = getaddrinfo(ptr, NULL, &hints, &result);
            if (res) {
                error_f("%s resolve failed:%s for type:%s\n", "A", ptr,
                        gai_strerror(res));
                free(cloned);
                return SSH_ERR_INTERNAL_ERROR;
            }
            for (tmp = result; tmp != NULL; tmp = tmp->ai_next) {
                ferrum_util_addr_to_ferrum_addr(tmp->ai_addr, addr);
                break;
            }
            freeaddrinfo(result);
        } else if (counter == 2) {
            port = atoi(ptr);
            if (addr->base.sa_family == AF_INET) {
                addr->v4.sin_port = htons(port);
            }
            if (addr->base.sa_family == AF_INET6) {
                addr->v6.sin6_port = htons(port);
            }
        }

        ptr = strtok(NULL, "#");
    }
    if (!port) {
        if (addr->base.sa_family == AF_INET) {
            addr->v4.sin_port = htons(defaultport);
        }
        if (addr->base.sa_family == AF_INET6) {
            addr->v6.sin6_port = htons(defaultport);
        }
    }

    free(cloned);
    return FERRUM_SUCCESS;
}

// cache some items for  resolution
static int64_t last_redis_resolve_time = 0;
static char redis_host[32];
static int32_t redis_port;

int32_t ferrum_create(ferrum_t **ferrum) {
    ferrum_t *tmp = malloc(sizeof(ferrum_t));
    if (!tmp) {
        error_f("ferrum malloc problem\n");
        return SSH_ERR_ALLOC_FAIL;
    }
    ferrum_fill_zero(tmp, sizeof(ferrum_t));

    int64_t current_time = ferrum_util_micro_time();
    if (current_time - last_redis_resolve_time >
        1 * 60 * 1000 * 1000) {  // every 1 minute only resolve again
        char *redis_env = getenv("REDIS_HOST");
        redis_env = redis_env ? redis_env : "localhost#6379";
        ferrum_sockaddr_t addr;
        int32_t result = ferrum_util_resolve(redis_env, &addr, 6379);
        if (result) {
            error_f("ferrum %s redis hostname resolution failed", redis_env);
            free(tmp);  // important
            return SSH_ERR_INTERNAL_ERROR;
        }
        ferrum_util_addr_to_ipport_string(&addr, redis_host, &redis_port, 0);
        last_redis_resolve_time = current_time;
    }
    verbose_f("redis host resolved to %s:%d", redis_host, redis_port);
    strcpy(tmp->redis.host, redis_host);
    tmp->redis.port = redis_port;

    char *login_url = getenv("LOGIN_URL");
    snprintf(tmp->login.url, FERRUM_LOGIN_URL_LEN - 1, "%s",
             login_url ? login_url : "http://localhost/login");

    *ferrum = tmp;
    return FERRUM_SUCCESS;
}
int32_t ferrum_destroy(ferrum_t *ferrum) {
    if (ferrum) free(ferrum);
    return FERRUM_SUCCESS;
}

int32_t ferrum_generate_session_id(ferrum_t *ferrum) {
    // init default ssed
    if (!srand_initted) {
        srand(time(NULL));
        srand_initted = 1;
    }
    size_t len = strlen(charset);
    for (uint32_t i = 0; i < sizeof(ferrum->session.id) - 1; ++i) {
        size_t index = rand() % len;
        ferrum->session.id[i] = charset[index];
    }
    ferrum->session.id[sizeof(ferrum->session.id) - 1] = 0;
    logit_f("ferrum session sid generated %s", ferrum->session.id);
    return FERRUM_SUCCESS;
}
int32_t ferrum_set_client_ip(ferrum_t *ferrum, const char *ip, int port) {
    if (ip)
        strncpy(ferrum->client.ipaddr, ip, sizeof(ferrum->client.ipaddr) - 1);
    if (port) ferrum->client.port = port;
    return FERRUM_SUCCESS;
}
int32_t ferrum_set_assigned_ip(ferrum_t *ferrum, const char *ip) {
    if (ip)
        strncpy(ferrum->assigned.ipaddr, ip,
                sizeof(ferrum->assigned.ipaddr) - 1);
    return FERRUM_SUCCESS;
}

int32_t ferrum_set_assigned_tunnel(ferrum_t *ferrum, const char *tunnel) {
    if (tunnel)
        strncpy(ferrum->assigned.tunnel, tunnel,
                sizeof(ferrum->assigned.tunnel) - 1);
    return FERRUM_SUCCESS;
}

int32_t ferrum_redis_connect(ferrum_t *ferrum) {
    if (ferrum->redis.context) {
        verbose_f("ferrum redis context is not null");
        return FERRUM_SUCCESS;
    }
    
    struct timeval timeout = {1, 500000};  // 1.5 seconds
    ferrum->redis.context = redisConnectWithTimeout(
        ferrum->redis.host, ferrum->redis.port, timeout);
    if (ferrum->redis.context == NULL || ferrum->redis.context->err) {
        if (ferrum->redis.context) {
            error_f("ferrum %s\n", ferrum->redis.context->errstr);
            return SSH_ERR_INTERNAL_ERROR;
            // handle error
        } else {
            error_f("ferrum can't allocate redis context");
            return SSH_ERR_INTERNAL_ERROR;
        }
    }
 
    return FERRUM_SUCCESS;
}
int32_t ferrum_redis_disconnect(ferrum_t *ferrum) {
    if (ferrum->redis.context) {
        redisFree(ferrum->redis.context);
        ferrum->redis.context = NULL;
    }
    return FERRUM_SUCCESS;
}
static int counter = 0;
int32_t ferrum_redis_test(ferrum_t *ferrum) {
    redisReply *reply =
        redisCommand(ferrum->redis.context, "set /redis/connected/total %d", counter++);
    if (reply == NULL) {  // timeout
        error_f("ferrum redis timeout");
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        error_f("ferrum redis reply error %s", reply->str);
    }
    freeReplyObject(reply);
    return FERRUM_SUCCESS;
}

int32_t ferrum_redis_subpubtest(ferrum_t *ferrum) {
    redisReply *reply =
        redisCommand(ferrum->redis.context, "subscribe /ferrum/pubsub/test");

    if (reply == NULL) {  // timeout
        error_f("ferrum redis timeout");
        freeReplyObject(reply);
        return SSH_ERR_INTERNAL_ERROR;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        freeReplyObject(reply);
        error_f("ferrum redis reply error %s", reply->str);
        return SSH_ERR_INTERNAL_ERROR;
    }
    freeReplyObject(reply);
    
    int32_t result = redisGetReply(ferrum->redis.context, (void *)&reply);
    if (result == REDIS_OK) {
        if (reply->type == REDIS_REPLY_ARRAY) {
            if (reply->elements >= 3) {
                if (!strcmp(reply->element[0]->str, "message")) {
                    char message[64];
                    strncpy(message, reply->element[2]->str,
                            sizeof(message) - 1);
                    verbose_f("ferrum pub/sub message %s",message);
                    freeReplyObject(reply);
                    return FERRUM_SUCCESS;
                }
            }
        }
        freeReplyObject(reply);
    } else {
        error_f("ferrum redis pub/sub error %s", ferrum->redis.context->errstr);
        return SSH_ERR_INTERNAL_ERROR;
    }
    return SSH_ERR_INTERNAL_ERROR;
}