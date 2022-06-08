#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <syslog.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define unused(x) (void)(x)

#ifndef UNUSED_ATTR
#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#define UNUSED_ATTR __attribute__((__unused__))
#else
#define UNUSED_ATTR
#endif
#endif

#define PAM_CONST const

#define FERRUM_PAM_SUCCESS 0
#define FERRUM_PAM_ERROR_REDIS 100

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
    struct pam_conv *conv;
    int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    return conv->conv(nargs, message, response, conv->appdata_ptr);
}
#define  log(pamh,priority,format,...) pam_syslog(pamh, priority, format, ##__VA_ARGS__)



static redisContext *redis_connect(pam_handle_t *pamh,const char *host,int32_t port){
 struct timeval timeout = { 1, 500000 }; // 1.5 seconds
     redisContext  *context= redisConnectWithTimeout(host,port,timeout);
    if (context == NULL || context->err) {
        if (context) {
            log(pamh,LOG_EMERG,"ferrum redis connect error: %s", context->errstr);
            return NULL;
            // handle error
        } else {
            log(pamh,LOG_EMERG,"ferrum can't allocate redis context");
            return NULL;
        }
    }
    log(pamh,LOG_DEBUG,"ferrum redis connected to %s#%d",host,port);
    return context;
}

static int counter=0;
static int32_t redis_test(pam_handle_t *pamh,redisContext *redis){
    
    
    redisReply *reply= redisCommand(redis,"set hamza %d ex 10",counter++);
    if(reply==NULL){//timeout
        log(pamh,LOG_EMERG,"ferrum redis timeout");
        freeReplyObject(reply);
        return FERRUM_PAM_ERROR_REDIS;
    }
    if(reply->type==REDIS_REPLY_ERROR){
        log(pamh,LOG_EMERG,"ferrum redis reply error %s",reply->str);
                freeReplyObject(reply);
        return FERRUM_PAM_ERROR_REDIS;
    }
    freeReplyObject(reply);
    return FERRUM_PAM_SUCCESS;

}

static int32_t redis_execute(pam_handle_t *pamh,redisContext *redis, const char *fmt,...){
    va_list args;
    va_start(args, fmt);
    redisReply *reply =
        redisvCommand(redis,fmt,args);
    if (reply == NULL) {  // timeout
        log(pamh, LOG_ALERT,"ferrum redis timeout");
        va_end(args);
        freeReplyObject(reply);
        return PAM_AUTH_ERR;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        log(pamh, LOG_ALERT,"ferrum redis reply error %s", reply->str);
        va_end(args);
        freeReplyObject(reply);
        return PAM_AUTH_ERR;
    }
    va_end(args);
    freeReplyObject(reply);
    return  PAM_SUCCESS;
}


static int32_t redis_wait_for_authentication(pam_handle_t *pamh,redisContext *redis,const char *session_id,const char *client_ip){
    
    // client source ip must be setted
    // we need to set a redis key like /session/${session_id} with some fields like clientIp   {clientIp:${clientIp}} for live to 5 minutes

    // create session object with identifier and clientIp
    int32_t result= redis_execute(pamh,redis,"hset /session/%s clientIp %s id %s",session_id,client_ip,session_id);
    if(result)return result;//error

    //set 5 minutes ttl, every client will update expire at every minute
    result= redis_execute(pamh,redis,"pexpire /session/%s 300000",session_id,client_ip,session_id);
    if(result)return result;//error


    result=redis_execute(pamh,redis,"subscribe /session/authentication/%s",session_id);
    if(result)return result;//error
   
   redisReply *reply;
    log(pamh, LOG_DEBUG,"ferrum redis pub/sub waiting authentication.%s", session_id);
    result = redisGetReply(redis, (void *)&reply);
    if (result == REDIS_OK) {
        if (reply->type == REDIS_REPLY_ARRAY) {
            if (reply->elements >= 3) {
                if (!strcmp(reply->element[0]->str, "message")) {
                    //char message[64];
                    //strncpy(message, reply->element[2]->str, sizeof(message) - 1);
                    log(pamh, LOG_DEBUG,"ferrum pub/sub message session: %s  msg: %s",session_id, reply->element[2]->str);
                    if(strncmp("ok:",reply->element[2]->str,3)==0){
                        freeReplyObject(reply);
                    return PAM_SUCCESS;
                    }
                }
            }
        }
        freeReplyObject(reply);
    } else {
        log(pamh, LOG_ALERT,"ferrum redis pub/sub error %s", redis->errstr);
        
    }
    return PAM_AUTH_ERR;

}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char *argv[]) {
    unused(pamh);
    unused(flags);
    //printf("Welcome hamza\n");
    log(pamh, LOG_DEBUG, "ferrum enter ");
	char **env=pam_getenvlist(pamh);
	while(*env){		
		log(pamh,LOG_DEBUG,"ferrum env: %s",*env);
		env++;
	}
    const char *client_ip= pam_getenv(pamh,"CLIENT_IP");
    const char *redis_host=pam_getenv(pamh,"REDIS_HOST");
    const char *redis_port=pam_getenv(pamh,"REDIS_PORT");
    const char *session_id=pam_getenv(pamh,"SESSION_ID");
    const char *login_url=pam_getenv(pamh,"LOGIN_URL");
    if(!client_ip || !redis_host || !redis_port || !session_id || !login_url){
        log(pamh,LOG_CRIT,"ferrum client ip  or redis host or redis port or session id or login url variable is null");
        return PAM_AUTH_ERR;
    }
    log(pamh,LOG_DEBUG,"ferrum client: %s redis: %s#%s session: %s login_url:%s",client_ip,redis_host,redis_port,session_id,login_url);
    log(pamh,LOG_INFO,"ferrum %s is authenticating",client_ip);
    redisContext *redis=redis_connect(pamh,redis_host,atoi(redis_port));
    if(!redis){
        return PAM_AUTH_ERR;
    }

    /* int32_t result=redis_test(pamh,redis);
    if(result){
    return PAM_AUTH_ERR;
    } */

    const char *pam_user;
    const char **ptr_pam_user = &pam_user;
    int32_t sshpam_err =
        pam_get_item(pamh, PAM_USER, (const void **)ptr_pam_user);

    if (!sshpam_err) {
        #define FERRUM_LOGIN_URL_LEN 512
        char ferrumlink[FERRUM_LOGIN_URL_LEN];
        snprintf(ferrumlink,FERRUM_LOGIN_URL_LEN-1, "ferrum_open:%s?session=%s",login_url,session_id);
        log(pamh, LOG_DEBUG, "ferrum user %s ", pam_user);
        PAM_CONST struct pam_message msg = {
            .msg_style = PAM_PROMPT_ECHO_ON,
            .msg = ferrumlink,
        };
        PAM_CONST struct pam_message *msgs = &msg;
        struct pam_response *resp = NULL;
        const int retval = converse(pamh, 1, &msgs, &resp);
        if (retval != PAM_SUCCESS) {
            log(pamh, LOG_ERR, "ferrum failed to inform user of error");
        }
		if(resp){
			if(resp->resp)
			free(resp->resp);
        free(resp);
		}
        log(pamh, LOG_DEBUG, "ferrum waiting for authentication");
        sshpam_err=redis_wait_for_authentication(pamh,redis,session_id,client_ip);
        
    }
	//return PAM_USER_UNKNOWN
    //return PAM_AUTH_ERR
    redisFree(redis);
    return (sshpam_err);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh UNUSED_ATTR,
                              int flags UNUSED_ATTR, int argc UNUSED_ATTR,
                              const char **argv UNUSED_ATTR) {
    //return PAM_SERVICE_ERR;
	return PAM_SUCCESS;
}



#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
    MODULE_NAME, pam_sm_authenticate, pam_sm_setcred, NULL, NULL, NULL, NULL};
#endif