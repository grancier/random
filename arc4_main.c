#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)
#define   MIN(a,b) (((a) < (b)) ? (a) : (b))


#define KEYSTREAM_ONLY
#include "chacha.h"

static int rs_initialized;
static pid_t rs_stir_pid;
static chacha_ctx rs;
static unsigned char rs_buf[RSBUFSZ];
static size_t rs_have;
static size_t rs_count;

void _rs_rekey(unsigned char *dat, size_t datlen);

void _rs_init(unsigned char *buf, size_t n)
{
    if (n < KEYSZ + IVSZ)
        return;
    chacha_keysetup(&rs, buf, KEYSZ * 8);
	chacha_ivsetup(&rs, buf + KEYSZ, 0);
}

void arc4random_stir(void)
{
    u_char rnd[KEYSZ + IVSZ];

    if (RAND_bytes(rnd, sizeof(rnd)) <= 0)
        printf("Couldn't obtain random bytes (error 0x%lx)",
               (unsigned long)ERR_get_error());

    if (!rs_initialized)
    {
        rs_initialized = 1;
        _rs_init(rnd, sizeof(rnd));
    }
    else
        _rs_rekey(rnd, sizeof(rnd));
    explicit_bzero(rnd, sizeof(rnd));

    rs_have = 0;
    memset(rs_buf, 0, RSBUFSZ);

    rs_count = 1600000;
}

void _rs_stir_if_needed(size_t len)
{
    pid_t pid = getpid();

    if (rs_count <= len || !rs_initialized || rs_stir_pid != pid)
    {
        rs_stir_pid = pid;
        arc4random_stir();
    }
    else
        rs_count -= len;
}

void _rs_rekey(unsigned char *dat, size_t datlen)
{
    chacha_encrypt_bytes(&rs, rs_buf, rs_buf, RSBUFSZ);

    if (dat)
    {
        size_t i, m;

        m = MIN(datlen, KEYSZ + IVSZ);

        for (i = 0; i < m; i++)
            rs_buf[i] ^= dat[i];
    }
    /* immediately reinit for backtracking resistance */
	_rs_init(rs_buf, KEYSZ + IVSZ);
	memset(rs_buf, 0, KEYSZ + IVSZ);
	rs_have = RSBUFSZ - KEYSZ - IVSZ;
}

void arc4random_buf(void *_buf, size_t n)
{
    unsigned char *buf = (unsigned char *)_buf;
    size_t m;

    _rs_stir_if_needed(n);
    while (n > 0) {
		if (rs_have > 0) {
			m = MIN(n, rs_have);
			memcpy(buf, rs_buf + RSBUFSZ - rs_have, m);
			memset(rs_buf + RSBUFSZ - rs_have, 0, m);
			buf += m;
			n -= m;
			rs_have -= m;
		}
		if (rs_have == 0)
			_rs_rekey(NULL, 0);
	}
}

void arc4random(u_int32_t *val)
{
    _rs_stir_if_needed(sizeof(*val));
    if (rs_have < sizeof(*val))
        _rs_rekey(NULL, 0); 
    memcpy(val, rs_buf + RSBUFSZ - rs_have, sizeof(*val));
    memset(rs_buf + RSBUFSZ - rs_have, 0, sizeof(*val));
    rs_have -= sizeof(*val);
    return;
}

void arc4random_addrandom(unsigned char *dat, int datlen)
{
    int m;
    if (!rs_initialized)
        arc4random_stir();
    while (datlen > 0)
    {
        m = MIN(datlen, KEYSZ + IVSZ);
        _rs_rekey(dat, m);
        dat += m;
        datlen -= m;
    };
}

u_int32_t arc4random_uniform(u_int32_t upper_bound)
{
    u_int32_t min, val;

    if (upper_bound < 2)
        return 0;

    /* 2**32 % x == (2**32 - x) % x */
    min = -upper_bound % upper_bound;

    /*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
    for (;;)
    {
        arc4random(&val);
        if (val >= min)
            break;
    }

    return val % upper_bound;
}

int main(int argc, char **argv)
{
    const int iter = 10;
    int i;
    u_int32_t val;

    for (i = 0; i < iter; i++)
    {
        arc4random(&val);
        printf("%u\n", val);
    }
    exit(0);
}