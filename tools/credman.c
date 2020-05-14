/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <fido.h>
#include <fido/credman.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

int
credman_get_metadata(fido_dev_t *dev, const char *path)
{
	fido_credman_metadata_t *metadata = NULL;
	char pin[1024];
	int r;

	if ((metadata = fido_credman_metadata_new()) == NULL)
		errx(1, "fido_credman_metadata_new");

	read_pin(path, pin, sizeof(pin));
	r = fido_credman_get_dev_metadata(dev, metadata, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_metadata: %s", fido_strerr(r));

	printf("existing rk(s): %u\n",
	    (unsigned)fido_credman_rk_existing(metadata));
	printf("remaining rk(s): %u\n",
	    (unsigned)fido_credman_rk_remaining(metadata));

	fido_credman_metadata_free(&metadata);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

static void
print_rp(fido_credman_rp_t *rp, size_t idx)
{
	char *rp_id_hash = NULL;

	if (base64_encode(fido_credman_rp_id_hash_ptr(rp, idx),
	    fido_credman_rp_id_hash_len(rp, idx), &rp_id_hash) < 0)
		errx(1, "output error");

	printf("%02u: %s %s\n", (unsigned)idx, rp_id_hash,
	    fido_credman_rp_id(rp, idx));

	free(rp_id_hash);
	rp_id_hash = NULL;
}

int
credman_list_rp(char *path)
{
	fido_dev_t *dev = NULL;
	fido_credman_rp_t *rp = NULL;
	char pin[1024];
	int r;

	if (path == NULL)
		usage();
	if ((rp = fido_credman_rp_new()) == NULL)
		errx(1, "fido_credman_rp_new");

	dev = open_dev(path);
	read_pin(path, pin, sizeof(pin));
	r = fido_credman_get_dev_rp(dev, rp, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_rp: %s", fido_strerr(r));

	for (size_t i = 0; i < fido_credman_rp_count(rp); i++)
		print_rp(rp, i);

	fido_credman_rp_free(&rp);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

static void
print_rk(const fido_credman_rk_t *rk, size_t idx)
{
	const fido_cred_t *cred;
	char *id = NULL;
	char *user_id = NULL;
	const char *type;
	const char *prot;

	if ((cred = fido_credman_rk(rk, idx)) == NULL)
		errx(1, "fido_credman_rk");
	if (base64_encode(fido_cred_id_ptr(cred), fido_cred_id_len(cred),
	    &id) < 0 || base64_encode(fido_cred_user_id_ptr(cred),
	    fido_cred_user_id_len(cred), &user_id) < 0)
		errx(1, "output error");

	switch (fido_cred_type(cred)) {
	case COSE_EDDSA:
		type = "eddsa";
		break;
	case COSE_ES256:
		type = "es256";
		break;
	case COSE_RS256:
		type = "rs256";
		break;
	default:
		type = "unknown";
		break;
	}

	switch (fido_cred_prot(cred)) {
	case FIDO_CRED_PROT_UV_OPTIONAL:
		prot = "PROT_UV_OPTIONAL";
		break;
	case FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID:
		prot = "PROT_UV_OPTIONAL_WITH_ID";
		break;
	case FIDO_CRED_PROT_UV_REQUIRED:
		prot = "PROT_UV_REQUIRED";
		break;
	default:
		prot = "PROT_UNKNOWN";
		break;
	}

	printf("%02u: %s %s (%s) %s %s\n", (unsigned)idx, id,
	    fido_cred_display_name(cred), user_id, type, prot);

	free(user_id);
	free(id);
	user_id = NULL;
	id = NULL;
}

int
credman_list_rk(char *path, const char *rp_id)
{
	fido_dev_t *dev = NULL;
	fido_credman_rk_t *rk = NULL;
	char pin[1024];
	int r;

	if (path == NULL)
		usage();
	if ((rk = fido_credman_rk_new()) == NULL)
		errx(1, "fido_credman_rk_new");

	dev = open_dev(path);
	read_pin(path, pin, sizeof(pin));
	r = fido_credman_get_dev_rk(dev, rp_id, rk, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_rk: %s", fido_strerr(r));
	for (size_t i = 0; i < fido_credman_rk_count(rk); i++)
		print_rk(rk, i);

	fido_credman_rk_free(&rk);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
credman_print_rk(fido_dev_t *dev, const char *path, char *rp_id, char *cred_id)
{
	const fido_cred_t *cred = NULL;
	fido_credman_rk_t *rk = NULL;
	char pin[1024];
	void *cred_id_ptr = NULL;
	size_t cred_id_len = 0;
	int r;

	if ((rk = fido_credman_rk_new()) == NULL)
		errx(1, "fido_credman_rk_new");
	if (base64_decode(cred_id, &cred_id_ptr, &cred_id_len) < 0)
		errx(1, "base64_decode");

	read_pin(path, pin, sizeof(pin));
	r = fido_credman_get_dev_rk(dev, rp_id, rk, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_rk: %s", fido_strerr(r));

	for (size_t i = 0; i < fido_credman_rk_count(rk); i++) {
		if ((cred = fido_credman_rk(rk, i)) == NULL ||
		    fido_cred_id_ptr(cred) == NULL)
			errx(1, "output error");
		if (cred_id_len != fido_cred_id_len(cred) ||
		    memcmp(cred_id_ptr, fido_cred_id_ptr(cred), cred_id_len))
			continue;
		print_cred(stdout, fido_cred_type(cred), cred);
		goto out;
	}

	errx(1, "credential not found");

out:
	free(cred_id_ptr);
	cred_id_ptr = NULL;

	fido_credman_rk_free(&rk);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
credman_delete_rk(fido_dev_t *dev, const char *path, char *id)
{
	char pin[1024];
	void *id_ptr = NULL;
	size_t id_len = 0;
	int r;

	if (base64_decode(id, &id_ptr, &id_len) < 0)
		errx(1, "base64_decode");

	read_pin(path, pin, sizeof(pin));
	r = fido_credman_del_dev_rk(dev, id_ptr, id_len, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_del_dev_rk: %s", fido_strerr(r));

	free(id_ptr);
	id_ptr = NULL;

	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

/*
 * pack_public_key_ecdsa and pack_public_key_ed25519 were modified from
 * functions of the same name in OpenSSH Portable 8.2, sk-usbhid.c. This file
 * contains the following copyright and license information:
 *
 * Copyright (c) 2019 Markus Friedl
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static int
pack_public_key_ecdsa(const fido_cred_t *cred, uint8_t *public_key)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	size_t public_key_len;
	int ret = -1;

	if ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		goto out;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		goto out;
	}
	if (fido_cred_pubkey_len(cred) != 64) {
		goto out;
	}

	if (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		goto out;
	}
	if (EC_POINT_set_affine_coordinates_GFp(g, q, x, y, NULL) != 1) {
		goto out;
	}
	public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (public_key_len != 65) {
		goto out;
	}
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    public_key, public_key_len, NULL) == 0) {
		goto out;
	}
	ret = 0;
out:
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

static int
pack_public_key_ed25519(const fido_cred_t *cred, uint8_t *public_key)
{
	const uint8_t *ptr;
	int ret = -1;

	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL)
		goto out;
	if (fido_cred_pubkey_len(cred) != 32)
		goto out;
	memcpy(public_key, ptr, 32);
	ret = 0;
out:
	return ret;
}

static const char SSH_SK_ECDSA_TYPE[] = "sk-ecdsa-sha2-nistp256@openssh.com ";
static uint8_t SSH_SK_ECDSA_PREFIX[] =
    {0x00, 0x00, 0x00, 0x22, 0x73, 0x6b, 0x2d, 0x65, 0x63, 0x64, 0x73, 0x61,
     0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32,
     0x35, 0x36, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63,
     0x6f, 0x6d, 0x00, 0x00, 0x00, 0x08, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32,
     0x35, 0x36, 0x00, 0x00, 0x00, 0x41};
static const char SSH_SK_ED25519_TYPE[] = "sk-ssh-ed25519@openssh.com ";
static uint8_t SSH_SK_ED25519_PREFIX[] =
    {0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
     0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20};

static char *
cred_ssh_pubkey(const fido_cred_t *cred, const char* rp_id) {
	const size_t rp_id_len = strlen(rp_id);
	const char *key_type;
	uint8_t *key_prefix;
	size_t key_prefix_len;
	size_t key_len;
	uint8_t *buf = NULL;
	size_t buf_len;
	char *enc_buf = NULL;
	int r;
	char *out = NULL;

	if (rp_id_len > UINT32_MAX)
		goto fail;

	switch (fido_cred_type(cred)) {
	case COSE_EDDSA:
		key_type = SSH_SK_ED25519_TYPE;
		key_prefix = SSH_SK_ED25519_PREFIX;
		key_prefix_len = sizeof(SSH_SK_ED25519_PREFIX);
		key_len = 32;
		break;
	case COSE_ES256:
		key_type = SSH_SK_ECDSA_TYPE;
		key_prefix = SSH_SK_ECDSA_PREFIX;
		key_prefix_len = sizeof(SSH_SK_ECDSA_PREFIX);
		key_len = 65;
		break;
	default:
		goto fail;
	}

	buf_len = key_prefix_len + key_len + 4 + rp_id_len;
	if ((buf = malloc(buf_len)) == NULL)
		goto fail;
	memcpy(buf, key_prefix, key_prefix_len);
	if (fido_cred_type(cred) == COSE_ES256)
		r = pack_public_key_ecdsa(cred, buf + key_prefix_len);
	else
		r = pack_public_key_ed25519(cred, buf + key_prefix_len);
	if (r != 0)
		goto fail;
	*(uint32_t *)(buf + key_prefix_len + key_len) = (uint32_t)rp_id_len;
	memcpy(buf + buf_len - rp_id_len, rp_id, rp_id_len);

	if (base64_encode(buf, buf_len, &enc_buf) < 0)
		goto fail;
	if ((out = calloc(1, key_prefix_len + strlen(enc_buf))) == NULL)
		goto fail;
	strcpy(out, key_type);
	strcat(out, enc_buf);
fail:
	free(buf);
	free(enc_buf);

	return (out);
}

static void
print_exposed_rp(const fido_credman_rp_t *rp, size_t idx) {
	printf("%02lu: RP ID: %s\n", idx, fido_credman_rp_id(rp, idx));
}

static void
print_exposed_cred(const fido_cred_t *cred, size_t idx, const char *rp_id) {
	char *user_id;
	char *key_handle;
	const char *type;
	int is_ssh;
	char *pubkey = NULL;

	if (base64_encode(fido_cred_user_id_ptr(cred),
	    fido_cred_user_id_len(cred), &user_id) < 0)
		user_id = strdup("<error>");

	if (base64_encode(fido_cred_id_ptr(cred), fido_cred_id_len(cred),
	    &key_handle) < 0)
		key_handle = strdup("<error>");

	is_ssh = (strncmp(rp_id, "ssh:", 4) == 0) ? 1 : 0;
	switch (fido_cred_type(cred)) {
	case COSE_EDDSA:
		type = "eddsa (Ed25519)";
		break;
	case COSE_ES256:
		type = "es256 (NIST P-256 with SHA-256)";
		break;
	case COSE_RS256:
		type = "rs256 (RSA with SHA-256)";
		is_ssh = 0;
		break;
	default:
		type = "unknown";
		is_ssh = 0;
	}

	printf("       %02lu: user ID: %s\n"
	       "           type: %s\n"
	       "           key handle: %s\n",
	       idx, user_id, type, key_handle);
	free(user_id);
	free(key_handle);

	if (is_ssh) {
		printf("           SSH public key:");
		if ((pubkey = cred_ssh_pubkey(cred, rp_id)) == NULL)
			printf(" <error>\n\n");
		else
			printf("\n%s\n\n", pubkey);
	}
}

static const char EXPOSED_INFO[] =
    "The following data about resident keys on the security key can potentially be\n"
    "obtained from the security key without a PIN, assuming knowledge of the\n"
    "respective RP ID:\n\n";

int
credman_list_exposed(char *path) {
	fido_dev_t *dev = NULL;
	fido_credman_rp_t *rp = NULL;
	fido_credman_rk_t *rk = NULL;
	const fido_cred_t *cred;
	const char *rp_id;
	char pin[1024];
	int exposed_found = 0;
	int rp_printed;
	int r;
	int ret = 1;

	if (path == NULL)
		usage();
	if ((rp = fido_credman_rp_new()) == NULL) {
		warnx("fido_credman_rp_new");
		goto fail;
	}
	if ((rk = fido_credman_rk_new()) == NULL) {
		warnx("fido_credman_rk_new");
		goto fail;
	}

	dev = open_dev(path);
	read_pin(path, pin, sizeof(pin));
	r = fido_credman_get_dev_rp(dev, rp, pin);

	if (r != FIDO_OK) {
		warnx("fido_credman_get_dev_rp: %s", fido_strerr(r));
		goto fail;
	}

	printf("%s", EXPOSED_INFO);
	for (size_t i = 0; i < fido_credman_rp_count(rp); i++) {
		rp_printed = 0;
		rp_id = fido_credman_rp_id(rp, i);
		if ((r = fido_credman_get_dev_rk(dev, rp_id, rk, pin))
		    != FIDO_OK) {
			warnx("fido_credman_get_dev_rk: %s", fido_strerr(r));
			goto fail;
		}
		for (size_t j = 0; j < fido_credman_rk_count(rk); j++) {
			if ((cred = fido_credman_rk(rk, j)) == NULL) {
				warnx("output error");
				goto fail;
			}
			if (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_OPTIONAL) {
				exposed_found = 1;
				if (!rp_printed) {
					print_exposed_rp(rp, i);
					rp_printed = 1;
				}
				print_exposed_cred(cred, j, rp_id);
			}
		}
	}
	if (!exposed_found)
		printf("None\n");

	ret = 0;
fail:
	explicit_bzero(pin, sizeof(pin));

	fido_credman_rk_free(&rk);
	fido_credman_rp_free(&rp);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(ret);
}
