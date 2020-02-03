#include "hazmat.h"
#include <assert.h>
#include <string.h>


static void test_key_shares()
{
	uint8_t key[32], restored[32];
	sss_Keyshare key_shares[256];
	size_t idx;

	for (idx = 0; idx < 32; idx++) {
		key[idx] = idx;
	}

	sss_create_keyshares(key_shares, key, 1, 1);
	sss_combine_keyshares(restored, key_shares, 1);
	assert(memcmp(key, restored, 32) == 0);

	sss_create_keyshares(key_shares, key, 3, 2);
	sss_combine_keyshares(restored, &key_shares[1], 2);
	assert(memcmp(key, restored, 32) == 0);

	sss_create_keyshares(key_shares, key, 255, 127);
	sss_combine_keyshares(restored, &key_shares[128], 127);
	assert(memcmp(key, restored, 32) == 0);

	sss_create_keyshares(key_shares, key, 255, 255);
	sss_combine_keyshares(restored, key_shares, 255);
	assert(memcmp(key, restored, 32) == 0);
}


int main()
{
	test_key_shares();
	return 0;
}
