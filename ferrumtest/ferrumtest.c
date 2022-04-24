#include "unit_ferrum_common.h"

extern int32_t test_ferrum();

int main(){
    if(test_ferrum())
    exit(1);
}