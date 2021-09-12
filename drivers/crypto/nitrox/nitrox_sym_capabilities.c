/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include "nitrox_sym_capabilities.h"

static const struct rte_cryptodev_capabilities nitrox_capabilities[] = {
	{	/* SHA1 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
				.block_size = 64,
				.key_size = {
					.minimum = 1,
					.maximum = 64,
					.increment = 1
				},
				.digest_size = {
					.minimum = 1,
					.maximum = 20,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA224 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA224_HMAC,
				.block_size = 64,
				.key_size = {
					.minimum = 1,
					.maximum = 64,
					.increment = 1
				},
				.digest_size = {
					.minimum = 1,
					.maximum = 28,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA256 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
				.block_size = 64,
				.key_size = {
					.minimum = 1,
					.maximum = 64,
					.increment = 1
				},
				.digest_size = {
					.minimum = 1,
					.maximum = 32,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* AES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_CBC,
				.block_size = 16,
				.key_size = {
					.minimum = 16,
					.maximum = 32,
					.increment = 8
				},
				.iv_size = {
					.minimum = 16,
					.maximum = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* 3DES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_3DES_CBC,
				.block_size = 8,
				.key_size = {
					.minimum = 24,
					.maximum = 24,
					.increment = 0
				},
				.iv_size = {
					.minimum = 8,
					.maximum = 8,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES GCM */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AEAD,
			{.aead = {
				.algo = RTE_CRYPTO_AEAD_AES_GCM,
				.block_size = 16,
				.key_size = {
					.minimum = 16,
					.maximum = 32,
					.increment = 8
				},
				.digest_size = {
					.minimum = 1,
					.maximum = 16,
					.increment = 1
				},
				.aad_size = {
					.minimum = 0,
					.maximum = 512,
					.increment = 1
				},
				.iv_size = {
					.minimum = 12,
					.maximum = 16,
					.increment = 4
				},
			}, }
		}, }
	},
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

const struct rte_cryptodev_capabilities *
nitrox_get_sym_capabilities(void)
{
	return nitrox_capabilities;
}
