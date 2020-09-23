/*
 * LUKS - Linux Unified Key Setup v2, TPM type token handler
 *
 * Copyright (C) 2018-2020 Fraunhofer SIT sponsorred by Infineon Technologies AG
 * Copyright (C) 2019-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019-2020 Daniel Zatovic
 * Copyright (C) 2019-2020 Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "utils_tpm2.h"
#include "libcryptsetup.h"
#include "../../src/plugin.h"

#define TOKEN_NAME "tpm2"
#define DEFAULT_TPM2_SIZE 64
#define DEFAULT_PCR_BANK "sha256"
#define MAX_TPM_COUNT "sha256"

#define NV_ARG		"plugin-tpm2-nv"
#define PCR_ARG		"plugin-tpm2-pcr"
#define BANK_ARG	"plugin-tpm2-bank"
#define DAPROTECT_ARG	"plugin-tpm2-daprotect"
#define NOPIN_ARG	"plugin-tpm2-no-pin"
#define TCTI_ARG	"plugin-tpm2-tcti"

#define CREATE_VALID	(1 << 0)
#define CREATED		(1 << 1)
#define REMOVE_VALID	(1 << 2)
#define REMOVED		(1 << 3)

#define TPMS_NO_LIMIT	100
#define TPMS_MAX_DIGITS	2	// TPM no. 0-99

static void tpm2_token_dump(struct crypt_device *cd, const char *json)
{
	uint32_t nvindex, uuid_nvindex, pcrs, pcrbanks;
	size_t nvkey_size;
	bool daprotect, pin;
	char buf[1024], num[32];
	unsigned i, n;

	if (tpm2_token_read(cd, json, &nvindex, &uuid_nvindex, &pcrs, &pcrbanks,
			    &daprotect, &pin, &nvkey_size)) {
		l_err(cd, "Cannot read JSON token metadata.");
		return;
	}

	l_std(cd, "\tNVindex:  0x%08" PRIx32 "\n", nvindex);
	l_std(cd, "\tUUID NVindex:  0x%08" PRIx32 "\n", uuid_nvindex);
	l_std(cd, "\tNVKey:    %zu [bytes]\n", nvkey_size);

	for (*buf = '\0', n = 0, i = 0; i < 32; i++) {
		if (!(pcrs & (1 << i)))
			continue;
		snprintf(num, sizeof(num), "%s%u", n ? "," : "", i);
		strcat(buf, num);
		n++;
	}
	l_std(cd, "\tPCRs:     %s\n", buf);

	*buf = '\0';
	n = 0;

	for (i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (pcrbanks & hash_algs[i].crypt_id) {
			if (n)
				strcat(buf, ",");
			strcat(buf, hash_algs[i].name);
			n++;
		}
	}

	l_std(cd, "\tPCRBanks: %s\n", buf);

	*buf = '\0';
	n = 0;
	if (daprotect) {
		strcat(buf, "DA_PROTECT");
		n++;
	}
	if (pin)
		strcat(buf, n++ ? ",PIN" : "PIN");
	l_std(cd, "\tflags:    %s\n", buf);
}

static int tpm2_token_open_pin_with_tcti(struct crypt_device *cd,
	int token,
	const char *tpm_pass,
	char **buffer,
	size_t *buffer_len,
	void *usrptr,
	const char *tcti_spec)
{
	int r;
	TSS2_RC tpm_rc;
	ESYS_CONTEXT *ctx;
	uint32_t nvindex, uuid_nvindex, pcrselection, pcrbanks;
	size_t nvkey_size;
	bool daprotect, pin;
	const char *json;
	size_t uuid_len;
	char *uuid_buffer = NULL;

	if (tpm_init(cd, &ctx, tcti_spec) != TSS2_RC_SUCCESS)
		return -EACCES;

	r = crypt_token_json_get(cd, token, &json);
	if (r < 0) {
		l_err(cd, "Cannot read JSON token metadata.");
		goto out;
	}

	r = tpm2_token_read(cd, json, &nvindex, &uuid_nvindex, &pcrselection, &pcrbanks,
			    &daprotect, &pin, &nvkey_size);
	if (r < 0) {
		l_err(cd, "Cannot read JSON token metadata.");
		goto out;
	}

	if (pin && !tpm_pass) {
		if (daprotect)
			l_std(cd, "TPM stored password has dictionary attack protection turned on. "
				  "Don't enter password too many times.\n");
		r = -EAGAIN;
		goto out;
	}

	uuid_len = strlen(crypt_get_uuid(cd));
	uuid_buffer = calloc(1, uuid_len);
	if (!uuid_buffer) {
		 r = -ENOMEM;
		 goto out;
	}

	tpm_rc = tpm_nv_read(cd, ctx, uuid_nvindex, NULL, 0, 0, CRYPT_TPM_PCRBANK_SHA1, uuid_buffer, uuid_len);
	if (tpm_rc != TPM2_RC_SUCCESS) {
		l_err(cd, "Failed to read UUID NV index, this TPM doesn't seem to hold the passphrase.");
		LOG_TPM_ERR(cd, tpm_rc);
		r = -EINVAL;
		goto out;
	}

	if (strncmp(crypt_get_uuid(cd), uuid_buffer, uuid_len)) {
		l_err(cd, "Bad UUID NV index content, this TPM doesn't hold the passphrase.");
		l_dbg(cd, "Real UUID: '%s'", crypt_get_uuid(cd));
		l_dbg(cd, "Read UUID: '%s'", uuid_buffer);
		r = -EINVAL;
		goto out;
	}

	*buffer = malloc(nvkey_size);
	if (!(*buffer)) {
		 r = -ENOMEM;
		 goto out;
	}
	*buffer_len = nvkey_size;

	r = -EACCES;

	tpm_rc = tpm_nv_read(cd, ctx, nvindex, tpm_pass, tpm_pass ? strlen(tpm_pass) : 0,
			   pcrselection, pcrbanks, *buffer, nvkey_size);

	if (tpm_rc == TSS2_RC_SUCCESS) {
		r = 0;
	} else if (tpm_rc == (TPM2_RC_S | TPM2_RC_1 | TPM2_RC_BAD_AUTH) ||
	           tpm_rc == (TPM2_RC_S | TPM2_RC_1 | TPM2_RC_AUTH_FAIL)) {
		l_err(cd, "Failed to read passphrase NV index.");
		LOG_TPM_ERR(cd, tpm_rc);
		r = -EPERM;
	}

out:
	if (uuid_buffer)
		free(uuid_buffer);
	Esys_Finalize(&ctx);
	return r;
}

static int tpm2_token_open_pin(struct crypt_device *cd,
	int token,
	const char *tpm_pass,
	char **buffer,
	size_t *buffer_len,
	void *usrptr)
{
	int access_error, i;

	l_std(cd, "Trying to activate with TPM backend: 'tabrmd'\n");
	int r = tpm2_token_open_pin_with_tcti(cd, token, tpm_pass, buffer, buffer_len,usrptr, "tabrmd");
	if (r != -EINVAL) {
		return r;
	}

	const size_t tcti_name_len = strlen("device:/dev/tpmrm") + TPMS_MAX_DIGITS + 1;
	char tcti_conf[tcti_name_len];

	for (i = 0; i < TPMS_NO_LIMIT; i++) {
		snprintf(tcti_conf, tcti_name_len, "device:/dev/tpmrm%d", i);
		l_dbg(cd, "Checking TPM device: '%s'\n", tcti_conf + 7);
		access_error = access(tcti_conf + 7, R_OK | W_OK);
		if (access_error) {
			l_dbg(cd, "Device does not exist", tcti_conf);
			break;
		}
		l_dbg(cd, "Device exists, trying to activate...", tcti_conf);
		l_std(cd, "Trying to activate with TPM backend: '%s'\n", tcti_conf);
		int r = tpm2_token_open_pin_with_tcti(cd, token, tpm_pass, buffer, buffer_len,usrptr, tcti_conf);
		if (r != -EINVAL) {
			return r;
		}
	}

	for (i = 0; i < TPMS_NO_LIMIT; i++) {
		snprintf(tcti_conf, tcti_name_len, "device:/dev/tpm%d", i);
		l_dbg(cd, "Checking TPM device: '%s'\n", tcti_conf + 7);
		access_error = access(tcti_conf + 7, R_OK | W_OK);
		if (access_error) {
			l_dbg(cd, "Device does not exist", tcti_conf);
			break;
		}
		l_dbg(cd, "Device exists, trying to activate...", tcti_conf);
		l_std(cd, "Trying to activate with TPM backend: '%s'\n", tcti_conf);
		int r = tpm2_token_open_pin_with_tcti(cd, token, tpm_pass, buffer, buffer_len,usrptr, tcti_conf);
		if (r != -EINVAL) {
			return r;
		}
	}

	return -EINVAL;
}

static int tpm2_token_open(struct crypt_device *cd,
	int token,
	char **buffer,
	size_t *buffer_len,
	void *usrptr)
{
	return tpm2_token_open_pin(cd, token, NULL, buffer, buffer_len, usrptr);
}

static int _tpm2_token_validate(struct crypt_device *cd, const char *json)
{
	return tpm2_token_validate(json);
}

struct tpm2_context {
	const char *tpmbanks_str;
	const char *tcti_str;
	uint32_t tpmbanks;
	uint32_t tpmnv;
	uint32_t tpmuuid_nv;
	uint32_t tpmpcrs;
	uint32_t pass_size;
	ESYS_CONTEXT *ctx;

	bool tpmdaprotect;
	bool no_tpm_pin;

	int timeout;
	int keyslot;
	int token;

	uint8_t status;

	struct crypt_cli *cli;
};

const crypt_token_handler cryptsetup_token_handler = {
	.name  = "tpm2",
	.open  = tpm2_token_open,
	.open_pin = tpm2_token_open_pin,
	.validate = _tpm2_token_validate,
	.dump = tpm2_token_dump
};

int crypt_token_handle_init(struct crypt_cli *cli, void **handle)
{
	int r;
	struct tpm2_context *tc;

	if (!handle)
		return -EINVAL;

	tc = calloc(1, sizeof(*tc));
	if (!tc)
		return -ENOMEM;

	r = tpm2_token_get_pcrbanks(DEFAULT_PCR_BANK, &tc->tpmbanks);
	if (r < 0) {
		free(tc);
		return r;
	}

	tc->cli = cli;

	*handle = tc;

	return 0;
}

void crypt_token_handle_free(void *handle)
{
	free(handle);
}

static const crypt_arg_list create_args[] = {
	/* plugin specific args */
	{ NV_ARG,	"Select TPM's NV index",                   CRYPT_ARG_UINT32, &create_args[1] },
	{ PCR_ARG,	"Selection of TPM PCRs",                   CRYPT_ARG_UINT32, &create_args[2] },
	{ BANK_ARG,	"Selection of TPM PCR banks", 		   CRYPT_ARG_STRING, &create_args[3] },
	{ DAPROTECT_ARG,"Enable TPM dictionary attack protection", CRYPT_ARG_BOOL,   &create_args[4] },
	{ NOPIN_ARG,	"Don't PIN protect TPM NV index",          CRYPT_ARG_BOOL,   &create_args[5] },
	{ TCTI_ARG,	"Select TCTI in format <tcti>:<tcti arg>, e.g. device:/dev/tpm0",               CRYPT_ARG_STRING, &create_args[6] },
	/* inherited from cryptsetup core args */
	{ "key-size",	NULL,                                      CRYPT_ARG_UINT32, &create_args[7] },
	{ "token-id",	NULL,                                      CRYPT_ARG_INT32,  &create_args[8] },
	{ "key-slot",	NULL,                                      CRYPT_ARG_INT32,  &create_args[9] },
	{ "timeout",	NULL,                                      CRYPT_ARG_UINT32, NULL }
};

static const crypt_arg_list remove_args[] = {
	/* plugin specific args */
	{ NV_ARG,	"Select TPM's NV index",                   CRYPT_ARG_UINT32, &remove_args[1] },
	{ TCTI_ARG,	"Select TCTI in format <tcti>:<tcti arg>, e.g. device:/dev/tpm0",               CRYPT_ARG_STRING, &remove_args[2] },
	/* inherited from cryptsetup core args */
	{ "token-id",	"Token number to remove",                                      CRYPT_ARG_INT32, NULL },
};

const crypt_arg_list *crypt_token_create_params(void)
{
	return create_args;
}

const crypt_arg_list *crypt_token_remove_params(void)
{
	return remove_args;
}

static int plugin_get_arg_value(struct crypt_device *cd, struct crypt_cli *cli, const char *key, crypt_arg_type_info type, void *rvalue)
{
	int r;
	crypt_arg_type_info ti;

	r = crypt_cli_arg_type(cli, key, &ti);
	if (r == -ENOENT)
		l_err(cd, "%s argument is not defined.", key);
	if (r)
		return r;

	if (ti != type) {
		l_err(cd, "%s argument type is unexpected.", key);
		return -EINVAL;
	}

	r = crypt_cli_arg_value(cli, key, rvalue);
	if (r)
		l_err(cd, "Failed to get %s value.", key);

	return r;
}

static int get_create_cli_args(struct crypt_device *cd, struct tpm2_context *tc)
{
	int r;

	r = plugin_get_arg_value(cd, tc->cli, "key-slot", CRYPT_ARG_INT32, &tc->keyslot);
	if (r)
		return r;

	r = plugin_get_arg_value(cd, tc->cli, "token-id", CRYPT_ARG_INT32, &tc->token);
	if (r)
		return r;

	if (crypt_cli_arg_set(tc->cli, "key-size")) {
		r = plugin_get_arg_value(cd, tc->cli, "key-size", CRYPT_ARG_UINT32, &tc->pass_size);
		if (r)
			return r;
	} else
		tc->pass_size = DEFAULT_TPM2_SIZE;

	r = plugin_get_arg_value(cd, tc->cli, "timeout", CRYPT_ARG_UINT32, &tc->timeout);
	if (r)
		return r;

	if (crypt_cli_arg_set(tc->cli, NV_ARG)) {
		r = plugin_get_arg_value(cd, tc->cli, NV_ARG, CRYPT_ARG_UINT32, &tc->tpmnv);
		if (r)
			return r;
	}

	if (crypt_cli_arg_set(tc->cli, PCR_ARG)) {
		r = plugin_get_arg_value(cd, tc->cli, PCR_ARG, CRYPT_ARG_UINT32, &tc->tpmpcrs);
		if (r)
			return r;
	}

	if (crypt_cli_arg_set(tc->cli, BANK_ARG)) {
		r = plugin_get_arg_value(cd, tc->cli, BANK_ARG, CRYPT_ARG_STRING, &tc->tpmbanks_str);
		if (r)
			return r;
	}

	if (crypt_cli_arg_set(tc->cli, TCTI_ARG)) {
		r = plugin_get_arg_value(cd, tc->cli, TCTI_ARG, CRYPT_ARG_STRING, &tc->tcti_str);
		if (r)
			return r;
	}

	tc->tpmdaprotect = crypt_cli_arg_set(tc->cli, DAPROTECT_ARG);
	tc->no_tpm_pin = crypt_cli_arg_set(tc->cli, NOPIN_ARG);

	return 0;
}

int crypt_token_validate_create_params(struct crypt_device *cd, void *handle)
{
	int r;
	struct tpm2_context *tc = (struct tpm2_context *)handle;

	if (!tc)
		return -EINVAL;

	r = get_create_cli_args(cd, tc);
	if (r)
		return r;

	if (tpm2_token_get_pcrbanks(tc->tpmbanks_str ?: DEFAULT_PCR_BANK, &tc->tpmbanks)) {
		l_err(cd, "Wrong PCR bank value.");
		return -EINVAL;
	}

	if (!tc->tpmbanks) {
		l_err(cd, "PCR banks must be selected.");
		return -EINVAL;
	}

	tc->status |= CREATE_VALID;

	return 0;
}

int crypt_token_create(struct crypt_device *cd, void *handle)
{
	char *existing_pass = NULL, *tpm_pin = NULL, *random_pass = NULL;
	size_t existing_pass_len, tpm_pin_len = 0;
	int r;
	bool supports_algs_for_pcrs;
	TSS2_RC tpm_rc;
	struct tpm2_context *tc = (struct tpm2_context *)handle;

	if (!tc)
		return -EINVAL;

	if (!tc->status) {
		r = crypt_token_validate_create_params(cd, handle);
		if (r)
			return r;
	}

	if (tc->status != CREATE_VALID)
		return -EINVAL;

	if (tc->tcti_str)
		l_dbg(cd, "initializing with TCTI %s", tc->tcti_str);
	else
		l_dbg(cd, "initializing with default TCTI");

	if (tpm_init(cd, &tc->ctx, tc->tcti_str) != TSS2_RC_SUCCESS)
		return -EINVAL;

	tpm_rc = tpm2_supports_algs_for_pcrs(cd, tc->ctx, tc->tpmbanks, tc->tpmpcrs, &supports_algs_for_pcrs);
	if (tpm_rc != TSS2_RC_SUCCESS) {
		l_err(NULL, "Failed to get PCRS capability from TPM.");
		LOG_TPM_ERR(NULL, tpm_rc);
		r = -ECOMM;
		goto out;
	}

	if (!supports_algs_for_pcrs) {
		l_err(NULL, "Your TPM doesn't support selected PCR and banks combination.");
		r = -ENOTSUP;
		goto out;
	}

	random_pass = crypt_safe_alloc(tc->pass_size);
	if (!random_pass) {
		r = -ENOMEM;
		goto out;
	}

	r = tpm_get_random(cd, tc->ctx, random_pass, tc->pass_size);
	if (r < 0)
		goto out;

	r = crypt_cli_get_key("Enter existing LUKS2 pasphrase:",
			  &existing_pass, &existing_pass_len,
			  0, 0, NULL, tc->timeout, 0, 0, cd, NULL);
	if (r < 0)
		goto out;

	if (!tc->no_tpm_pin) {
		r = crypt_cli_get_key("Enter new TPM password:",
				  &tpm_pin, &tpm_pin_len,
				  0, 0, NULL, tc->timeout, 1, 0, cd, NULL);
		if (r < 0)
			goto out;
	}

	r = tpm_nv_find_and_write(cd, tc->ctx,  &tc->tpmnv, random_pass, tc->pass_size, tpm_pin, tpm_pin_len, tc->tpmbanks, tc->tpmpcrs, tc->tpmdaprotect);
	if (r < 0) {
		l_err(cd, "Failed to write passphrase to an NV index.");
		goto out;
	}


	r = tpm_nv_find_and_write(cd, tc->ctx,  &tc->tpmuuid_nv, crypt_get_uuid(cd), strlen(crypt_get_uuid(cd)), NULL, 0,CRYPT_TPM_PCRBANK_SHA1, 0, false);
	if (r < 0) {
		l_err(cd, "Failed to write disk UUID to an NV index.");
		goto err_pass_nv_defined;
	}

	r = crypt_keyslot_add_by_passphrase(cd, tc->keyslot, existing_pass, existing_pass_len, random_pass, tc->pass_size);
	if (r < 0) {
		if (r == -EPERM)
			l_err(cd, "Wrong LUKS2 passphrase supplied.");
		goto err_uuid_nv_defined;
	}
	tc->keyslot = r;
	l_std(cd, "Using keyslot %d.\n", tc->keyslot);

	r = tpm2_token_add(cd, tc->token, tc->tpmnv, tc->tpmuuid_nv, tc->tpmpcrs, tc->tpmbanks, tc->tpmdaprotect, !tc->no_tpm_pin, tc->pass_size);
	if (r < 0) {
		goto err_keyslot_created;
	}
	tc->token = r;
	l_std(cd, "Token: %d\n", tc->token);

	r = crypt_token_assign_keyslot(cd, tc->token, tc->keyslot);
	if (r < 0) {
		l_err(cd, "Failed to assign keyslot %d to token %d.", tc->keyslot, tc->token);
		crypt_token_json_set(cd, tc->token, NULL);
		goto err_keyslot_created;
	}

	if (r > 0) {
		r = 0;
		tc->status |= CREATED;
	}
	goto out;

err_keyslot_created:
	crypt_keyslot_destroy(cd, tc->keyslot);
err_uuid_nv_defined:
	tpm_nv_undefine(cd, tc->ctx, tc->tpmuuid_nv);
	tc->tpmuuid_nv = 0;
err_pass_nv_defined:
	tpm_nv_undefine(cd, tc->ctx, tc->tpmnv);
	tc->tpmnv = 0;
out:
	crypt_safe_free(random_pass);
	crypt_safe_free(existing_pass);
	crypt_safe_free(tpm_pin);

	Esys_Finalize(&tc->ctx);
	return r;
}

static int get_remove_cli_args(struct crypt_device *cd, struct tpm2_context *tc)
{
	int r;

	r = plugin_get_arg_value(cd, tc->cli, "token-id", CRYPT_ARG_INT32, &tc->token);
	if (r)
		return r;

	if (crypt_cli_arg_set(tc->cli, NV_ARG)) {
		r = plugin_get_arg_value(cd, tc->cli, NV_ARG, CRYPT_ARG_UINT32, &tc->tpmnv);
		if (r)
			return r;
	}

	return 0;
}

int crypt_token_validate_remove_params(struct crypt_device *cd, void *handle)
{
	int r;
	struct tpm2_context *tc = (struct tpm2_context *)handle;

	if (!tc || tc->status)
		return -EINVAL;

	r = get_remove_cli_args(cd, tc);
	if (r)
		return r;

	if (tc->token < 0 && tc->token != CRYPT_ANY_TOKEN) {
		l_err(cd, "Invalid token specification.");
		return -EINVAL;
	}

	if (!tc->tpmnv && tc->token == CRYPT_ANY_TOKEN) {
		l_err(cd, "Token ID or TPM2 nvindex option must be specified.");
		return -EINVAL;
	}

	tc->status = REMOVE_VALID;

	return 0;
}

int crypt_token_remove(struct crypt_device *cd, void *handle)
{
	int i, r;
	const char *type;
	struct tpm2_context *tc = (struct tpm2_context *)handle;

	if (!tc)
		return -EINVAL;

	if (!tc->status) {
		r = crypt_token_validate_remove_params(cd, handle);
		if (r)
			return r;
	}

	if (tc->status != REMOVE_VALID)
		return -EINVAL;

	if (tc->token == CRYPT_ANY_TOKEN)
		tc->token = tpm2_token_by_nvindex(cd, tc->tpmnv);

	if (tc->token < 0 ||
	    crypt_token_status(cd, tc->token, &type) != CRYPT_TOKEN_EXTERNAL ||
	    strcmp(type, "tpm2")) {
		l_err(cd, "No TPM2 token to destroy.");
		return -EINVAL;
	}

	/* Destroy all keyslots assigned to TPM 2 token */
	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++) {
		if (!crypt_token_is_assigned(cd, tc->token, i)) {
			r = crypt_keyslot_destroy(cd, i);
			if (r < 0) {
				l_err(cd, "Cannot destroy keyslot %d.", i);
				return r;
			}
		}
	}

	if (tpm_init(cd, &tc->ctx, tc->tcti_str) != TSS2_RC_SUCCESS)
		return -EINVAL;

	/* Destroy TPM2 NV index and token object itself */
	r = tpm2_token_kill(cd, tc->ctx, tc->token);
	if (!r)
		tc->status |= REMOVED;

	Esys_Finalize(&tc->ctx);
	return r;
}
