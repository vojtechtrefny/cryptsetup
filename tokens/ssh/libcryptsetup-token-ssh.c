/*
 * Example of LUKS2 keyslot handler, token lib
 *
 * Copyright (C) 2016-2020 Milan Broz <gmazyland@gmail.com>
 * Copyright (C) 2020 Vojtech Trefny
 *
 * Use:
 *  - generate LUKS device
 *  - store passphrase used in previous step remotely (single line w/o \r\n)
 *  - add new token using this example
 *  - activate device by token
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include "libcryptsetup.h"
#include "../../src/plugin.h"

#define PASSWORD_LENGTH 8192

#define TOKEN_NAME "ssh"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

#define SERVER_ARG	"plugin-ssh-server"
#define USER_ARG	"plugin-ssh-user"
#define PATH_ARG	"plugin-ssh-path"
#define KEYPATH_ARG	"plugin-ssh-keypath"

#define CREATE_VALID	(1 << 0)
#define CREATED 	(1 << 1)

#define l_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define l_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)

typedef int (*password_cb_func) (char **password);

struct sshplugin_context {
	const char *server;
	const char *user;
	const char *path;
	const char *sshkey_path;

	int token;
	int keyslot;

	uint8_t status;

	struct crypt_cli *cli;
};

int crypt_token_handle_init(struct crypt_cli *cli, void **handle)
{
	struct sshplugin_context *sc;

	if (!handle)
		return -EINVAL;

	sc = calloc(1, sizeof(*sc));
	if (!sc)
		return -ENOMEM;

	sc->cli = cli;

	*handle = sc;

	return 0;
}

void crypt_token_handle_free(void *handle)
{
	free(handle);
}

const char *crypt_token_version(void)
{
	return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR;
}

const static crypt_arg_list args[] = {
	/* plugin specific args */
	{ SERVER_ARG,	"SSH server URL",			CRYPT_ARG_STRING, &args[1] },
	{ USER_ARG,	"SSH username",            		CRYPT_ARG_STRING, &args[2] },
	{ PATH_ARG,	"Path to the keyfile on SSH server", 	CRYPT_ARG_STRING, &args[3] },
	{ KEYPATH_ARG,  "Path to the SSH key to use",		CRYPT_ARG_STRING, &args[4] },
	/* inherited from cryptsetup core args */
	{ "token-id",	NULL,                                   CRYPT_ARG_INT32,  &args[5] },
	{ "key-slot",	NULL,                                   CRYPT_ARG_INT32,  NULL },
};

const crypt_arg_list *crypt_token_create_params(void)
{
	return args;
}

static json_object *get_token_jobj(struct crypt_device *cd, int token)
{
	const char *json_slot;

	/* libcryptsetup API call */
	if (crypt_token_json_get(cd, token, &json_slot))
		return NULL;

	return json_tokener_parse(json_slot);
}

static int sshplugin_download_password(struct crypt_device *cd, ssh_session ssh,
	const char *path, char **password, size_t *password_len)
{
	char *pass = NULL;
	size_t pass_len;
	int r;
	sftp_attributes sftp_attr = NULL;
	sftp_session sftp = NULL;
	sftp_file file = NULL;


	sftp = sftp_new(ssh);
	if (!sftp) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot create sftp session: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_init(sftp);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot init sftp session: ");
		goto out;
	}

	file = sftp_open(sftp, path, O_RDONLY, 0);
	if (!file) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot create sftp session: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	sftp_attr = sftp_fstat(file);
	if (!sftp_attr) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot stat sftp file: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	pass_len = sftp_attr->size > PASSWORD_LENGTH ? PASSWORD_LENGTH : sftp_attr->size;
	pass = malloc(pass_len);
	if (!pass) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Not enough memory.\n");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_read(file, pass, pass_len);
	if (r < 0 || (size_t)r != pass_len) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot read remote key: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	*password = pass;
	*password_len = pass_len;

	r = SSH_OK;
out:
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
		free(pass);
	}

	if (sftp_attr)
		sftp_attributes_free(sftp_attr);

	if (file)
		sftp_close(file);
	if (sftp)
		sftp_free(sftp);
	return r == SSH_OK ? 0 : -EINVAL;
}

static ssh_session sshplugin_session_init(struct crypt_device *cd,
	const char *host, const char *user)
{
	int r, port = 22;
	ssh_session ssh = ssh_new();
	if (!ssh)
		return NULL;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
	ssh_options_set(ssh, SSH_OPTIONS_USER, user);
	ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

	crypt_log(cd, CRYPT_LOG_NORMAL, "SSH token initiating ssh session.\n");

	r = ssh_connect(ssh);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Connection failed: ");
		goto out;
	}

	r = ssh_session_is_known_server(ssh);
	if (r != SSH_SERVER_KNOWN_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Server not known: ");
		r = SSH_AUTH_ERROR;
		goto out;
	}

	r = SSH_OK;

	/* initialise list of authentication methods. yes, according to official libssh docs... */
	ssh_userauth_none(ssh, NULL);
out:
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
		ssh_disconnect(ssh);
		ssh_free(ssh);
		ssh = NULL;
	}

	return ssh;
}

static int sshplugin_public_key_auth(struct crypt_device *cd, ssh_session ssh, const ssh_key pkey)
{
	int r;

	crypt_log(cd, CRYPT_LOG_DEBUG, "Trying public key authentication method.\n");

	if (!(ssh_userauth_list(ssh, NULL) & SSH_AUTH_METHOD_PUBLICKEY)) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key auth method not allowed on host.\n");
		return SSH_AUTH_ERROR;
	}

	r = ssh_userauth_try_publickey(ssh, NULL, pkey);
	if (r == SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_DEBUG, "Public key method accepted.\n");
		r = ssh_userauth_publickey(ssh, NULL, pkey);
	}

	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key authentication error: ");
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	return r;
}

static int SSHPLUGIN_open_pin(struct crypt_device *cd, int token, const char *pin,
	char **password, size_t *password_len, void *usrptr)
{
	int r;
	json_object *jobj_server, *jobj_user, *jobj_path, *jobj_token, *jobj_keypath;
	ssh_key pkey;
	ssh_session ssh;

	jobj_token = get_token_jobj(cd, token);
	json_object_object_get_ex(jobj_token, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_token, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_token, "ssh_path",   &jobj_path);
	json_object_object_get_ex(jobj_token, "ssh_keypath",&jobj_keypath);

	r = ssh_pki_import_privkey_file(json_object_get_string(jobj_keypath), pin, NULL, NULL, &pkey);
	if (r != SSH_OK) {
		if (r == SSH_EOF) {
			crypt_log(cd, CRYPT_LOG_ERROR, "Failed to open and import private key.\n");
			return -EINVAL;
		}
		crypt_log(cd, CRYPT_LOG_ERROR, "Failed to import private key (password protected?).\n");
		return -EAGAIN;
	}

	ssh = sshplugin_session_init(cd, json_object_get_string(jobj_server),
				   json_object_get_string(jobj_user));
	if (!ssh) {
		ssh_key_free(pkey);
		return -EINVAL;
	}

	r = sshplugin_public_key_auth(cd, ssh, pkey);
	ssh_key_free(pkey);

	if (r == SSH_AUTH_SUCCESS)
		r = sshplugin_download_password(cd, ssh, json_object_get_string(jobj_path),
					      password, password_len);

	ssh_disconnect(ssh);
	ssh_free(ssh);

	return r ? -EINVAL : r;
}

static int SSHPLUGIN_open(struct crypt_device *cd, int token,
	char **password, size_t *password_len, void *usrptr)
{
	return SSHPLUGIN_open_pin(cd, token, NULL, password, password_len, usrptr);
}

static void SSHPLUGIN_dump(struct crypt_device *cd, const char *json)
{
	json_object *jobj_token, *jobj_server, *jobj_user, *jobj_path, *jobj_keypath;
	char buf[4096];

	jobj_token = json_tokener_parse(json);
	if (!jobj_token)
		return;

	json_object_object_get_ex(jobj_token, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_token, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_token, "ssh_path",   &jobj_path);
	json_object_object_get_ex(jobj_token, "ssh_keypath",&jobj_keypath);

	snprintf(buf, sizeof(buf) - 1, "\tssh_server: %s\n\tssh_user: %s\n"
		"\tssh_path: %s\n\tssh_key_path: %s\n",
		json_object_get_string(jobj_server),
		json_object_get_string(jobj_user),
		json_object_get_string(jobj_path),
		json_object_get_string(jobj_keypath));

	crypt_log(cd, CRYPT_LOG_NORMAL, buf);
	json_object_put(jobj_token);
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

int crypt_token_validate_create_params(struct crypt_device *cd, void *handle) {
	int r;

	struct sshplugin_context *sc = (struct sshplugin_context *)handle;

	if (!sc)
		return -EINVAL;

	if (crypt_cli_arg_set(sc->cli, "token-id")) {
		r = plugin_get_arg_value(cd, sc->cli, "token-id", CRYPT_ARG_INT32, &sc->token);
		if (r)
			return r;
	} else
		sc->token = CRYPT_ANY_TOKEN;

	if (crypt_cli_arg_set(sc->cli, "key-slot")) {
		r = plugin_get_arg_value(cd, sc->cli, "key-slot", CRYPT_ARG_INT32, &sc->keyslot);
		if (r)
			return r;
	} else
		sc->keyslot = 0;

	if (crypt_cli_arg_set(sc->cli, SERVER_ARG)) {
		r = plugin_get_arg_value(cd, sc->cli, SERVER_ARG, CRYPT_ARG_STRING, &sc->server);
		if (r)
			return r;
	} else {
		l_err(cd, "SSH server URL must be specified.");
		return -EINVAL;
	}

	if (crypt_cli_arg_set(sc->cli, USER_ARG)) {
		r = plugin_get_arg_value(cd, sc->cli, USER_ARG, CRYPT_ARG_STRING, &sc->user);
		if (r)
			return r;
	} else {
		l_err(cd, "Username must be specified.");
		return -EINVAL;
	}

	if (crypt_cli_arg_set(sc->cli, PATH_ARG)) {
		r = plugin_get_arg_value(cd, sc->cli, PATH_ARG, CRYPT_ARG_STRING, &sc->path);
		if (r)
			return r;
	} else {
		l_err(cd, "Key path must be specified.");
		return -EINVAL;
	}

	if (crypt_cli_arg_set(sc->cli, KEYPATH_ARG)) {
		r = plugin_get_arg_value(cd, sc->cli, KEYPATH_ARG, CRYPT_ARG_STRING, &sc->sshkey_path);
		if (r)
			return r;
	} else {
		l_err(cd, "SSH key path must be specified.");
		return -EINVAL;
	}

	sc->status |= CREATE_VALID;

	return 0;
}

static int sshplugin_token_add(struct crypt_device *cd,
	int token,
	const char *server,
	const char *user,
	const char *path,
	const char *keypath)
{
	json_object *jobj = NULL;
	json_object *jobj_keyslots = NULL;
	const char *string_token;
	int r;

	jobj = json_object_new_object();
	if (!jobj)
		return -EINVAL;

	/* type is mandatory field in all tokens and must match handler name member */
	json_object_object_add(jobj, "type", json_object_new_string(TOKEN_NAME));

	jobj_keyslots = json_object_new_array();

	/* mandatory array field (may be empty and assigned later */
	json_object_object_add(jobj, "keyslots", jobj_keyslots);

	/* custom metadata */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));
	json_object_object_add(jobj, "ssh_keypath", json_object_new_string(keypath));

	string_token = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
	if (!string_token) {
		r = -EINVAL;
		goto out;
	}

	l_dbg(cd, "Token JSON: %s\n", string_token);

	r = crypt_token_json_set(cd, token, string_token);
out:
	json_object_put(jobj);
	return r;
}

int crypt_token_create(struct crypt_device *cd, void *handle) {
	int r;
	struct sshplugin_context *sc = (struct sshplugin_context *)handle;

	if (!sc)
		return -EINVAL;

	if (!sc->status) {
		r = crypt_token_validate_create_params(cd, handle);
		if (r)
			return r;
	}

	if (sc->status != CREATE_VALID)
		return -EINVAL;

	r = sshplugin_token_add(cd, sc->token, sc->server, sc->user, sc->path, sc->sshkey_path);
	if (r < 0) {
		l_err(cd, "Failed to add token.");
		return r;
	}


	sc->token = r;
	l_dbg(cd, "Token: %d\n", sc->token);

	r = crypt_token_assign_keyslot(cd, sc->token, sc->keyslot);
	if (r < 0) {
		l_err(cd, "Failed to assign keyslot %d to token %d.", sc->keyslot, sc->token);
		crypt_token_json_set(cd, sc->token, NULL);
	}

	if (r > 0) {
		r = 0;
		sc->status |= CREATED;
	}

	return r;
}

const crypt_token_handler cryptsetup_token_handler = {
	.name  = "ssh",
	.open  = SSHPLUGIN_open,
	.open_pin = SSHPLUGIN_open_pin,
	.dump  = SSHPLUGIN_dump,
};
