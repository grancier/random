/* $OpenBSD: chacha-merged.c,v 1.9 2019/01/22 00:59:21 dlg Exp $ */
/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

#define CHACHA_MINKEYLEN 	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

struct chacha_ctx {
	u_int input[16];
	uint8_t ks[CHACHA_BLOCKLEN];
	uint8_t unused;
};

void chacha_keysetup(struct chacha_ctx *x, const u_char *k, u_int kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u_char *iv, const u_char *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m, u_char *c, u_int bytes);
void arc4random(u_int32_t *val);

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct chacha_ctx chacha_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

/* Initialise with "expand 32-byte k". */
static const char sigma[16] = {
	0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
	0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
};

/* Initialise with "expand 16-byte k". */
static const char tau[16] = {
	0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x31,
	0x36, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
};
