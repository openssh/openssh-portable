#include "ferrum_test_common.h"

extern int32_t test_ferrum_test();

int main(){
    if(test_ferrum_test())
    exit(1);
}