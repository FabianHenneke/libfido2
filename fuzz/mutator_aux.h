/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _MUTATOR_AUX_H
#define _MUTATOR_AUX_H

#include <stddef.h>
#include <stdint.h>
#include <cbor.h>

/*
 * As of LLVM 10.0.0, MSAN support in libFuzzer was still experimental.
 * We therefore have to be careful when using our custom mutator, or
 * MSAN will flag uninitialised reads on memory populated by libFuzzer.
 * Since there is no way to suppress MSAN without regenerating object
 * code (in which case you might as well rebuild libFuzzer with MSAN),
 * we adjust our mutator to make it less accurate while allowing
 * fuzzing to proceed.
 */

#if defined(__has_feature)
# if  __has_feature(memory_sanitizer)
#  include <sanitizer/msan_interface.h>
#  define NO_MSAN	__attribute__((no_sanitize("memory")))
#  define WITH_MSAN	1
# endif
#endif

#if !defined(WITH_MSAN)
# define NO_MSAN
#endif

#define MAXSTR	1024
#define MAXBLOB	3072

struct blob {
	uint8_t body[MAXBLOB];
	size_t len;
};

struct param;

struct param *unpack(const uint8_t *, size_t);
size_t pack(uint8_t *, size_t, const struct param *);
size_t pack_dummy(uint8_t *, size_t);
void mutate(struct param *, unsigned int);
void test(const struct param *);

size_t xstrlen(const char *);
void consume(const void *, size_t);
void consume_str(const char *);

int unpack_blob(cbor_item_t *, struct blob *);
int unpack_byte(cbor_item_t *, uint8_t *);
int unpack_int(cbor_item_t *, int *);
int unpack_string(cbor_item_t *, char *);

cbor_item_t *pack_blob(const struct blob *);
cbor_item_t *pack_byte(uint8_t);
cbor_item_t *pack_int(int);
cbor_item_t *pack_string(const char *);

void mutate_byte(uint8_t *);
void mutate_int(int *);
void mutate_blob(struct blob *);
void mutate_string(char *);

void *dev_open(const char *);
void dev_close(void *);
void set_wire_data(const uint8_t *, size_t);
int dev_read(void *, unsigned char *, size_t, int);
int dev_write(void *, const unsigned char *, size_t);

void prng_init(unsigned long);
unsigned long prng_uint32(void);

uint32_t uniform_random(uint32_t);

#endif /* !_MUTATOR_AUX_H */
