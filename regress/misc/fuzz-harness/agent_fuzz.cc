// cc_fuzz_target test for ssh-agent.
extern "C" {

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <sys/types.h>

extern void test_one(const uint8_t* s, size_t slen);

int LLVMFuzzerTestOneInput(const uint8_t* s, size_t slen)
{
	test_one(s, slen);
	return 0;
}

} // extern
