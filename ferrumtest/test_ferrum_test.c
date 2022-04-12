#include "ferrum_test_common.h"
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
static void test_object_create_destroy_success(void **start)
{
    unused(start);
}

int32_t test_ferrum_test(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_object_create_destroy_success),

    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
