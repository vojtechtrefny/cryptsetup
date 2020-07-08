/*
 * cli tokens plugins helpers
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
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

#ifdef USE_EXTERNAL_CLI_TOKENS
#include <assert.h>
#include <dlfcn.h>
#endif

#include "cryptsetup.h"

#ifdef USE_EXTERNAL_CLI_TOKENS
static const struct poptOption popt_table_end = POPT_TABLEEND;

static int tools_plugin_load_symbol(const char *symbol, void *handle, bool quiet, void **ret_symbol)
{
	char *error;
	void *sym = dlsym(handle, symbol);

	error = dlerror();
	if (error) {
		if (!quiet)
			log_err(_("Failed to load mandatory plugin symbol %s (%s)."), symbol, error);
		return -EINVAL;
	}

	*ret_symbol = sym;

	return 0;
}

static void tools_plugin_load_optional_symbol(const char *symbol, void *handle, void **ret_symbol)
{
	char *error;
	void *sym = dlsym(handle, symbol);

	error = dlerror();
	if (error) {
		log_dbg("Failed to load optional plugin symbol %s (%s).", symbol, error);
		return;
	}

	*ret_symbol = sym;
}

static int dlopen_plugin(const char *type, struct tools_token_handler *th, bool quiet)
{
	char plugin[64];
	void *h;
	int r = snprintf(plugin, sizeof(plugin), "libcryptsetup-token-%s.so", type);

	log_dbg("Loading plugin %s.", plugin);

	if (r < 0 || (size_t)r >= sizeof(plugin))
		return -EINVAL;

	r = -EINVAL;
	h = dlopen(plugin, RTLD_LAZY);
	if (!h) {
		if (!quiet)
			log_err("Failed to load cryptsetup plugin: %s.", dlerror());
		return r;
	}
	dlerror();

	r = tools_plugin_load_symbol("crypt_token_handle_init", h, quiet, (void **)&th->init);
	if (r)
		goto out;

	r = tools_plugin_load_symbol("crypt_token_handle_free", h, quiet, (void **)&th->free);
	if (r)
		goto out;

	r = tools_plugin_load_symbol("crypt_token_version", h, quiet, (void **)&th->version);
	if (r)
		goto out;

	tools_plugin_load_optional_symbol("crypt_token_create", h, (void **)&th->create);
	if (th->create) {
		r = tools_plugin_load_symbol("crypt_token_create_params", h, quiet, (void **)&th->create_params);
		if (r)
			goto out;
	}

	tools_plugin_load_optional_symbol("crypt_token_remove", h, (void **)&th->remove);
	if (th->remove) {
		r = tools_plugin_load_symbol("crypt_token_remove_params", h, quiet, (void **)&th->remove_params);
		if (r)
			goto out;
	}

	tools_plugin_load_optional_symbol("crypt_token_validate_create_params", h, (void **)&th->validate_create_params);

	tools_plugin_load_optional_symbol("crypt_token_validate_remove_params", h, (void **)&th->validate_remove_params);

	th->loaded = true;
	th->dlhandle = h;
	r = 0;
out:
	if (r)
		dlclose(h);
	return r;
}

static int tools_find_arg_id_in_args(const char *name, struct tools_arg *args, size_t args_len)
{
	int i;

	if (!args)
		return -EINVAL;

	for (i = 0; i < (int)args_len; i++)
		if (args[i].name && !strcmp(name, args[i].name))
			return i;

	return -ENOENT;
}

static int add_plugin_arg(struct tools_token_handler *thandle, const char *name, crypt_arg_type_info arg_type)
{
	int r;

	r = tools_find_arg_id_in_args(name, thandle->args_plugin, thandle->total_args_count);
	if (r == -ENOENT) {
		r = thandle->total_args_count++;
		thandle->args_plugin[r].name = name;
		thandle->args_plugin[r].type = arg_type;
	}

	return r;
}

static int plugin_add_options(struct tools_token_handler *thandle,
		const crypt_arg_list* (*params)(void),
		size_t private_args_count,
		size_t total_args_count,
		struct poptOption r_top_opts[3],
		struct poptOption **r_private_opts,
		struct poptOption **r_ref_opts,
		struct tools_arg *core_args,
		size_t core_args_len,
		struct poptOption *popt_basic_options,
		void *plugin_cb)
{
	int i, r = -ENOMEM;
	const crypt_arg_list *item;
	size_t ref_len = 0, last = 0, plg_cnt = 0, ref_cnt = 0;
	struct poptOption *plugin_opts = NULL, *ref_opts = NULL;

	if (!total_args_count || !params)
		return 0;

	item = params();

	if (total_args_count > private_args_count)
		ref_len = total_args_count - private_args_count;

	if (private_args_count) {
		if (private_args_count < SIZE_MAX / sizeof(*plugin_opts) - 2)
			plugin_opts = malloc((private_args_count + 2) * sizeof(*plugin_opts));
		if (!plugin_opts)
			goto out;

		plugin_opts[0].shortName = '\0';
		plugin_opts[0].argInfo = POPT_ARG_CALLBACK;
		plugin_opts[0].arg = plugin_cb;
		plugin_opts[0].descrip = (const char *)thandle;

		r_top_opts[last].argInfo = POPT_ARG_INCLUDE_TABLE;
		r_top_opts[last++].arg = plugin_opts;
	}

	if (ref_len) {
		if (ref_len < SIZE_MAX / sizeof(*ref_opts) - 1)
			ref_opts = malloc((ref_len + 1) * sizeof(*ref_opts));
		if (!ref_opts)
			goto out;

		r_top_opts[last].argInfo = POPT_ARG_INCLUDE_TABLE;
		r_top_opts[last++].arg = ref_opts;
	}

	r_top_opts[last] = popt_table_end;

	while (item) {
		if (strncmp(item->name, "plugin-", 7)) {
			if (ref_cnt >= ref_len) {
				r = -EINVAL;
				log_dbg("Plugin core arguments references being inconsistent.");
				goto out;
			}
			i = tools_find_arg_id_in_args(item->name, core_args, core_args_len);
			if (i > 0) {
				ref_opts[ref_cnt] = popt_basic_options[i];
				/* replace with plugin specific description if provided */
				if (item->desc)
					ref_opts[ref_cnt].descrip = item->desc;
				ref_cnt++;
			}
			item = item->next;
			continue;
		}

		if (plg_cnt >= private_args_count) {
			r = -EINVAL;
			log_dbg("Plugin arguments reporting being inconsistent.");
			goto out;
		}

		r = add_plugin_arg(thandle, item->name + strlen(thandle->type) + 8, item->arg_type);
		if (r < 0)
			goto out;

		plugin_opts[plg_cnt+1].longName = item->name;
		switch (item->arg_type) {
		case CRYPT_ARG_BOOL:
			plugin_opts[plg_cnt+1].argInfo = POPT_ARG_NONE;
			break;
		case CRYPT_ARG_STRING:
		case CRYPT_ARG_INT32:
		case CRYPT_ARG_UINT32:
		case CRYPT_ARG_INT64:
		case CRYPT_ARG_UINT64:
			plugin_opts[plg_cnt+1].argInfo = POPT_ARG_STRING;
			break;
		}
		plugin_opts[plg_cnt+1].descrip = item->desc;
		plg_cnt++;
		item = item->next;
	}

	if (plugin_opts)
		plugin_opts[plg_cnt+1] = popt_table_end;
	if (ref_opts)
		ref_opts[ref_cnt] = popt_table_end;

	*r_private_opts = plugin_opts;
	*r_ref_opts = ref_opts;

	return 0;
out:
	free(plugin_opts);
	free(ref_opts);

	return r;
}

static int validate_plugin_args(const char *type,
		const crypt_arg_list *(*params)(void),
		struct tools_arg *core_args,
		size_t core_args_len,
		size_t *r_private_args_count,
		size_t *r_total_args_count)
{
	size_t n, private_args = 0, args = 0;
	const crypt_arg_list *item = params ? params() : NULL;

	while (item) {
		if (!item->name || item->arg_type > CRYPT_ARG_UINT64)
			return -EINVAL;
		log_dbg("Validating plugin parameter %s (type %d).", item->name, item->arg_type);
		if (!strncmp(item->name, "plugin-", 7)) {
			/* plugin specific argument must be prefixed with "plugin-<type>-" */
			n = strlen(type);
			if (strncmp(item->name + 7, type, n)) {
				log_dbg("Invalid argument %s name (expected: plugin-%s-<name>).", item->name, type);
				return -EINVAL;
			}
			if ((*(item->name + n + 7) != '-') || !*(item->name + n + 8)) {
				log_dbg("Invalid argument %s name (expected: plugin-%s-<name>).", item->name, type);
				return -EINVAL;
			}
			private_args++;
		} else {
			if (tools_find_arg_id_in_args(item->name, core_args, core_args_len) < 0) {
				log_dbg("Plugin requests access to undefined core argument %s.", item->name);
				return -EINVAL;
			}
		}

		args++;
		item = item->next;
	}

	*r_private_args_count = private_args;
	*r_total_args_count = args;

	return 0;
}

static int plugin_allocate_internal(struct tools_token_handler *thandle,
		size_t create_private_args_count,
		size_t remove_private_args_count)
{
	struct tools_arg *args = NULL;
	size_t len = create_private_args_count + remove_private_args_count;

	/* size_t overflow check */
	if (len < create_private_args_count ||
	    len < remove_private_args_count)
		return -ENOMEM;

	if (!len)
		return 0;

	if (len < SIZE_MAX / sizeof(*args))
		args = malloc(len * sizeof(*args));
	if (!args)
		return -ENOMEM;

	thandle->args_plugin = args;

	return 0;
}

int tools_plugin_load(const char *type,
		struct poptOption *plugin_options,
		struct tools_token_handler *token_handler,
		struct tools_arg *core_args,
		size_t core_args_len,
		struct poptOption *popt_core_options,
		void *plugin_cb,
		bool quiet)
{
	int r;
	size_t last_id = 0, create_private_args_count = 0, create_args_count = 0,
	       remove_private_args_count = 0, remove_args_count = 0;

	r = dlopen_plugin(type, token_handler, quiet);
	if (r)
		return r;

	r = validate_plugin_args(token_handler->type, token_handler->create_params,
				 core_args, core_args_len, &create_private_args_count, &create_args_count);
	if (r) {
		if (!quiet)
			log_err(_("Plugin %s create parameters are invalid."), type);
		goto out;
	}

	r = validate_plugin_args(token_handler->type, token_handler->remove_params,
				 core_args, core_args_len, &remove_private_args_count, &remove_args_count);
	if (r) {
		if (!quiet)
			log_err(_("Plugin %s remove parameters are invalid."), type);
		goto out;
	}

	r = plugin_allocate_internal(token_handler, create_private_args_count, remove_private_args_count);
	if (r)
		goto out;

	r = plugin_add_options(token_handler,
			       token_handler->create_params,
			       create_private_args_count,
			       create_args_count,
			       token_handler->popt_create_args,
			       &token_handler->popt_create_plg_args,
			       &token_handler->popt_create_ref_args,
			       core_args,
			       core_args_len,
			       popt_core_options,
			       plugin_cb);
	if (r)
		goto out;

	r = plugin_add_options(token_handler,
			       token_handler->remove_params,
			       remove_private_args_count,
			       remove_args_count,
			       token_handler->popt_remove_args,
			       &token_handler->popt_remove_plg_args,
			       &token_handler->popt_remove_ref_args,
			       core_args,
			       core_args_len,
			       popt_core_options,
			       plugin_cb);
	if (r)
		goto out;

	if (create_args_count) {
		r = asprintf(&token_handler->create_desc, N_("Plugin %s token add action arguments:"), type);
		if (r < 0)
			goto out;
		token_handler->popt_table_plugin[last_id].longName = NULL;
		token_handler->popt_table_plugin[last_id].shortName = '\0';
		token_handler->popt_table_plugin[last_id].argInfo = POPT_ARG_INCLUDE_TABLE;
		token_handler->popt_table_plugin[last_id].arg = token_handler->popt_create_args;
		token_handler->popt_table_plugin[last_id].descrip = token_handler->create_desc;
		token_handler->popt_table_plugin[last_id].val = 0;
		token_handler->popt_table_plugin[last_id++].argDescrip = NULL;
	}

	if (remove_args_count) {
		r = asprintf(&token_handler->remove_desc, N_("Plugin %s token remove action arguments:"), type);
		if (r < 0)
			goto out;
		token_handler->popt_table_plugin[last_id].longName = NULL;
		token_handler->popt_table_plugin[last_id].shortName = '\0';
		token_handler->popt_table_plugin[last_id].argInfo = POPT_ARG_INCLUDE_TABLE;
		token_handler->popt_table_plugin[last_id].arg = token_handler->popt_remove_args;
		token_handler->popt_table_plugin[last_id].descrip = token_handler->remove_desc;
		token_handler->popt_table_plugin[last_id].val = 0;
		token_handler->popt_table_plugin[last_id++].argDescrip = NULL;
	}

	token_handler->popt_table_plugin[last_id] = popt_table_end;

	plugin_options->longName = NULL;
	plugin_options->shortName = '\0';
	plugin_options->argInfo = POPT_ARG_INCLUDE_TABLE;
	plugin_options->arg = &token_handler->popt_table_plugin;
	plugin_options->val = 0;
	plugin_options->argDescrip = NULL;

	r = 0;
out:
	if (r)
		tools_plugin_unload(token_handler);

	return r;
}

void tools_plugin_unload(struct tools_token_handler *th)
{
	if (!th || !th->type)
		return;

	if (th->loaded)
		dlclose(th->dlhandle);

	free(CONST_CAST(void *)th->type);
	free(CONST_CAST(void *)th->create_desc);
	free(CONST_CAST(void *)th->remove_desc);

	tools_args_free(th->args_plugin, th->total_args_count);

	free(th->args_plugin);
	free(th->popt_create_ref_args);
	free(th->popt_create_plg_args);
	free(th->popt_remove_ref_args);
	free(th->popt_remove_plg_args);

	memset(th, 0, sizeof(*th));
}

static bool args_add_action(const char *action, struct tools_arg *args, size_t args_size, unsigned arg_id)
{
	unsigned i;

	for (i = 0; i < MAX_ACTIONS && args[arg_id].actions_array[i]; i++) {
		if (!strcmp(args[arg_id].actions_array[i], action))
			return true;
	}

	if (i >= MAX_ACTIONS)
		return false;

	/* do not restrict otherwise global arguments */
	if (i)
		args[arg_id].actions_array[i] = action;

	return true;
}

static void assign_args_to_action(const crypt_arg_list *(*params)(void),
		struct tools_arg *args,
		size_t args_len,
		const char *action)
{
	int p;
	const crypt_arg_list *item;

	if (!params)
		return;

	item = params();
	while (item) {
		if (strncmp(item->name, "plugin-", 7)) {
			p = tools_find_arg_id_in_args(item->name, args, args_len);
			assert(p > 0);
			assert(args_add_action(action, args, args_len, p));
		}
		item = item->next;
	}
}

void tools_plugin_assign_args_to_action(struct tools_token_handler *thandle,
		struct tools_arg *args,
		size_t args_len,
		const char *action)
{
	assign_args_to_action(thandle->create_params, args, args_len, action);
	assign_args_to_action(thandle->remove_params, args, args_len, action);
}
#else
int tools_plugin_load(const char *type,
		struct poptOption *plugin_options,
		struct tools_token_handler *token_handler,
		struct tools_arg *core_args,
		size_t core_args_len,
		struct poptOption *popt_core_options,
		void *plugin_cb,
		bool quiet)
{
	return -ENOTSUP;
}

void tools_plugin_unload(struct tools_token_handler *th)
{
}

void tools_plugin_assign_args_to_action(struct tools_token_handler *thandle,
		struct tools_arg *args,
		size_t args_len,
		const char *action)
{
}
#endif //USE_EXTERNAL_CLI_TOKENS
