#include "unit_ferrum_common.h"
#include "../ferrum/ferrum.h"
#define unused(x) (void)(x)
static int setup(void **state)
{
    unused(state);
    fprintf(stdout, "****  %s ****\n", __FILE__);
    return 0;
}

static int teardown(void **state)
{
    unused(state);
    return 0;
}
static void test_ferrum_create_destroy(void **start)
{
    ferrum_t *fer;
    
    int32_t result=ferrum_create(&fer);
    assert_int_equal(result,FERRUM_SUCCESS);
    unused(start);
    assert_string_equal(fer->redis.host,"127.0.0.1");
    assert_int_equal(fer->redis.port,6379);
    assert_string_equal(fer->login.url,"http://localhost/login");
    ferrum_destroy(fer);


}
static void test_ferrum_generate_session_id(void **start)
{
    ferrum_t *fer;
    int32_t result=ferrum_create(&fer);
    assert_int_equal(result,FERRUM_SUCCESS);
    result=ferrum_generate_session_id(fer);
    assert_int_equal(result,FERRUM_SUCCESS);
    printf("%s %zu\n",fer->session.id,strlen(fer->session.id));
    assert_true(strlen(fer->session.id)==63);
    unused(start);
    ferrum_destroy(fer);
}

static void test_field_sets(void **start)
{
    unused(start);
    ferrum_t *fer;
      int32_t result=ferrum_create(&fer);
    assert_int_equal(result,FERRUM_SUCCESS);
    
    result=ferrum_set_client_ip(fer,"1.1.1.1",53);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_string_equal(fer->client.ipaddr,"1.1.1.1");
    assert_int_equal(fer->client.port,53);

    result=ferrum_set_assigned_ip(fer,"192.168.1.2");
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_string_equal(fer->assigned.ipaddr,"192.168.1.2");

    result=ferrum_set_assigned_tunnel(fer,"tun110");
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_string_equal(fer->assigned.tunnel,"tun110");
    ferrum_destroy(fer);
    
}

static void test_ferrum_util_ipport_to_addr(void **start){
    unused(start);
    ferrum_sockaddr_t addr;
    int32_t result=ferrum_util_ipport_to_addr("1.2.3.4",9090,&addr);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_int_equal(addr.v4.sin_family,AF_INET);
    assert_int_equal(addr.v4.sin_port,33315);
    assert_int_equal(addr.v4.sin_addr.s_addr,67305985);

    result=ferrum_util_ipport_to_addr("::1",9091,&addr) ;
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_int_equal(addr.v6.sin6_family,AF_INET6);
    assert_int_equal(addr.v6.sin6_port,33571);
    
}
static void test_ferrum_util_addr_to_ipport_string(void **start){
    unused(start);
    ferrum_sockaddr_t addr;
    int32_t result=ferrum_util_ipport_to_addr("1.2.3.4",9090,&addr);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_int_equal(addr.v4.sin_family,AF_INET);
    assert_int_equal(addr.v4.sin_port,33315);
    assert_int_equal(addr.v4.sin_addr.s_addr,67305985);  
    //check 
    int32_t port;
    char buffer[FERRUM_IP_STRING_LEN];
    result=ferrum_util_addr_to_ipport_string(&addr,buffer,&port,0);
    assert_string_equal(buffer,"1.2.3.4");  
    assert_int_equal(port,9090);
    ferrum_util_addr_to_ipport_string(&addr,buffer,&port,1);
    assert_string_equal(buffer,"1.2.3.4#9090"); 
    assert_int_equal(port,9090);
}

static void test_ferrum_util_addr_to_ferrum_addr(void **start){
    unused(start);
    struct sockaddr_in v4;
    v4.sin_family=AF_INET;
    inet_pton(AF_INET,"1.2.3.4",&v4.sin_addr);
    ferrum_sockaddr_t ferrum;
    int32_t result=ferrum_util_addr_to_ferrum_addr((struct sockaddr*)&v4,&ferrum);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_int_equal(v4.sin_addr.s_addr,ferrum.v4.sin_addr.s_addr);

}
static void test_ferrum_util_resolve(void **start){
    unused(start);
    ferrum_sockaddr_t addr;
    memset(&addr,0, sizeof(addr));

    int32_t result=ferrum_util_resolve(NULL,&addr,3030);
    assert_int_not_equal(result,FERRUM_SUCCESS);
    
    result=ferrum_util_resolve("www.google.com",&addr,443);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_true(addr.v4.sin_addr.s_addr>0);
    assert_int_equal(addr.v4.sin_port,htons(443));


    result=ferrum_util_resolve("www.google.com#80",&addr,443);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_true(addr.v4.sin_addr.s_addr>0);
    assert_int_equal(addr.v4.sin_port,htons(80));


    result=ferrum_util_resolve("#80",&addr,443);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_true(addr.v4.sin_addr.s_addr>0);
    assert_int_equal(addr.v4.sin_port,htons(443));

    result=ferrum_util_resolve("1.1.1.1#80",&addr,443);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_true(addr.v4.sin_addr.s_addr>0);
    assert_int_equal(addr.v4.sin_port,htons(80));

    result=ferrum_util_resolve("www.sabah.com.tr#80",&addr,443);
    assert_int_equal(result,FERRUM_SUCCESS);
    assert_true(addr.v4.sin_addr.s_addr>0);
    assert_int_equal(addr.v4.sin_port,htons(80));

}



int32_t test_ferrum(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ferrum_create_destroy),
        cmocka_unit_test(test_ferrum_generate_session_id),
        cmocka_unit_test(test_field_sets),
        cmocka_unit_test(test_ferrum_util_ipport_to_addr),
        cmocka_unit_test(test_ferrum_util_addr_to_ipport_string),
        cmocka_unit_test(test_ferrum_util_addr_to_ferrum_addr),
        cmocka_unit_test(test_ferrum_util_resolve),

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
