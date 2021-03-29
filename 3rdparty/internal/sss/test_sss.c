#include "sss.h"
#include <assert.h>
#include <string.h>

int main()
{
	unsigned char data[sss_MLEN] = { 42 }, restored[sss_MLEN];
	sss_Share shares[256];
	int tmp;

	/* Normal operation */
	sss_create_shares(shares, data, 1, 1);
	tmp = sss_combine_shares(restored, shares, 1);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

	/* A lot of shares */
	sss_create_shares(shares, data, 255, 255);
	tmp = sss_combine_shares(restored, shares, 255);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

	/* Not enough shares to restore secret */
	sss_create_shares(shares, data, 100, 100);
	tmp = sss_combine_shares(restored, shares, 99);
	assert(tmp == -1);

	/* Too many secrets should also restore the secret */
	sss_create_shares(shares, data, 200, 100);
	tmp = sss_combine_shares(restored, shares, 200);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

	return 0;
}
