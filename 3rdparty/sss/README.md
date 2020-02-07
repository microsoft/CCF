# Shamir secret sharing library

[![Build Status](https://travis-ci.org/dsprenkels/sss.svg?branch=master)](https://travis-ci.org/dsprenkels/sss)

`sss` is a library that exposes an API to split secret data buffers into
a number of different _shares_. With the possession of some or all of these
shares, the original secret can be restored. It is the schoolbook example of
a cryptographic _threshold scheme_. ([demo])

## Table of contents

1. [Introduction](#introduction)
2. [Download](#download)
3. [Usage](#usage)
	1. [Example](#example)
4. [Bindings](#bindings)
5. [Technical details](#technical-details)
6. [Comparison of secret sharing libraries](#comparison-of-secret-sharing-libraries)
7. [Questions](#questions)

## Introduction

An example use case is a beer brewery which has a vault which contains their
precious super secret recipe. The 5 board members of this brewery do not trust
all the others well enough that they won't secretly break into the vault and
sell the recipe to a competitor. So they split the code into 5 shares, and
allow 4 shares to restore the original code. Now they are sure that the
majority of the staff will know when the vault is opened, but they can still
open the vault when one of the staff members is abroad or sick at home.

As often with crypto libraries, there is a lot of Shamir secret sharing code
around that *does not meet cryptographic standards* (a.k.a. is insecure).
Some details—like integrity checks and side-channel resistance—are often
forgotten. But these slip-ups can often fully compromise the security of the
scheme.
With this in mind, I have made this library to:
- Be side channel resistant
- Secure the shared secret with a MAC
- Use the platform (OS) randomness source

It should be safe to use this library in "the real world", but note that until
the release of version 1.0 the API may be changed without backward
compatibility.

## Download

Currently, I have not packaged this library yet, but I expect to do so very
soon. If you are planning to use the library, please drop me an email and I will
freeze the API spec. So for now you should use the following command to get the
code:

```shell
git clone --recursive https://github.com/dsprenkels/sss.git
```

## Usage

Secrets are provided as arrays of 64 bytes long. This should be big enough to
store generally small secrets. If you wish to split larger chunks of data, you
can use symmetric encryption and split the key instead. Shares are generated
from secret data using `sss_create_shares` and shares can be combined again
using the `sss_combine_shares` functions. The shares are a octet strings of
113 bytes each.

### Example

```c
#include "sss.h"
#include "randombytes.h"
#include <assert.h>
#include <string.h>

int main()
{
	uint8_t data[sss_MLEN], restored[sss_MLEN];
	sss_Share shares[5];
	size_t idx;
	int tmp;

	/* Create a message [42, 42, ..., 42] */
	for (idx = 0; idx < sizeof(data), ++idx) {
		data[idx] = 42;
	}

	/* Split the secret into 5 shares (with a recombination theshold of 4) */
	sss_create_shares(shares, data, 5, 4);

	/* Combine some of the shares to restore the original secret */
	tmp = sss_combine_shares(restored, shares, 4);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);
}
```

## Bindings

I have currently written bindings for the following languages:

- [Node.js](https://github.com/dsprenkels/sss-node)
- [Go](https://github.com/dsprenkels/sss-go)
- [Rust](https://github.com/dsprenkels/sss-rs)

## Technical details

Shamir secret sharing works by generating a polynomial (e.g. _33x³ + 8x² + 29x +
42_). The lowest term is the term is the secret and is just filled in. All the
other terms are generated randomly. Then we can pick points on the polynomial
by filling in values for _x_. Each point is put in a share. Afterwards, with _k_
points we can use interpolation to restore a _k_-degree polynomial.

In practice there is a wrapper around the secret-sharing part (this is
done because of crypto-technical reasons). This wrapper uses the
Salsa20/Poly1305 authenticated encryption scheme. Because of this, the
shares are always a little bit larger than the original data.

This library uses a custom [`randombytes`][randombytes] function to generate a
random encapsulation key, which talks directly to the operating system. When
using the high level API, you are not allowed to choose your own key. It _must_
be uniformly random, because regularities in secret-shared can be exploited.

With the low level API (`hazmat.h`) you _can_ choose to secret-share a piece of
data of exactly 32 bytes. This produces a set of shares that are much shorter
than the high-level shares (namely 33 bytes each). However, keep in mind that
this module is called `hazmat.h` (for "hazardous materials") for a reason.
Please only use this if you _really_ know what you are doing. Raw "textbook"
Shamir secret sharing is only safe when using a uniformly random secret (with
128 bits of entropy). Note also that it is entirely insecure for integrity.
Please do not use the low-level API unless you _really_ have no other choice.

## Comparison of secret-sharing libraries

If you would like your library to be added here, please open a pull request. :)

| Library         | Side-channels | Tamper-resistant | Secret length |
|-----------------|---------------|------------------|---------------|
| [B. Poettering] | Insecure¹     | Insecure         | 128 bytes     |
| [libgfshare]    | Insecure²     | Insecure         | ∞             |
| [blockstack]    | ??³           | Insecure         | 160 bytes     |
| [sssa-golang]   | Secure        | Secure⁴          | ∞             |
| [sssa-ruby]     | ??³           | Secure⁴          | ∞             |
| [snipsco]       | Secure        | Insecure         | Note⁶         |
| [dsprenkels]    | Secure        | Secure⁵          | 64 bytes      |

### Notes

1. Uses the GNU gmp library.
2. Uses lookup tables for GF(256) multiplication.
3. This library is implemented in a high level scripting library which does not
   guarantee that its basic operators execute in constant-time.
4. Uses randomized *x*-coordinates.
5. Uses randomized *y*-coordinates.
6. When using the [snipsco] library you will have to specify your own prime.
   Computation time is _O(p²)_, so on a normal computer you will be limited to
   a secret size of ~1024 bytes.

[B. Poettering]: http://point-at-infinity.org/ssss/
[libgfshare]: http://www.digital-scurf.org/software/libgfshare
[blockstack]: https://github.com/blockstack/secret-sharing
[sssa-golang]: https://github.com/SSSaaS/sssa-golang
[sssa-ruby]: https://github.com/SSSaaS/sssa-ruby
[snipsco]: https://github.com/snipsco/rust-threshold-secret-sharing
[dsprenkels]: https://github.com/dsprenkels/sss


## Questions

Feel free to send me an email on my Github associated e-mail address.

[demo]: https://dsprenkels.com/sss/
[randombytes]: https://github.com/dsprenkels/randombytes
