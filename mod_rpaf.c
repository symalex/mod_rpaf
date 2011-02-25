#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"
#include "inet_ntop_cache.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/**
 * this is a rpaf lighttpd plugin
 */

/* plugin config for all request/connections */
typedef struct {
    int enabled;        // 1-enable plugin, 0-disable plugin
    int sethostname;    // 1-set host name from headers("X-Forwarded-Host"/"X-Host"), 0-disabled
    buffer *headername; // header name or used "X-Forwarded-For" for remote IP
    array *proxy_ips;   // proxy IP list for handling (for example ["127.0.0.1", "10.0.0.10"])
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_rpaf_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	return p;
}

/* destroy the plugin data */
FREE_FUNC(mod_rpaf_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

                        if (s->headername) buffer_free(s->headername);
                        if (s->proxy_ips) array_free(s->proxy_ips);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */
SETDEFAULTS_FUNC(mod_rpaf_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
                { "rpaf.enable",            NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },         /* 0 */
                { "rpaf.proxy_ips",         NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },         /* 1 */
                { "rpaf.sethostname",       NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },         /* 2 */
                { "rpaf.header",            NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },        /* 3 */
		{ NULL,                     NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
                s->enabled = 0;
                s->proxy_ips = array_init();
                s->sethostname = 0;
                s->headername = buffer_init();

                cv[0].destination = &s->enabled;
                cv[1].destination = s->proxy_ips;
                cv[2].destination = &s->sethostname;
                cv[3].destination = s->headername;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
#define USED(n) (buffer_is_equal_string(du->key, CONST_STR_LEN(n)))
static int mod_rpaf_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

        PATCH(enabled);
        PATCH(proxy_ips);
        PATCH(sethostname);
        PATCH(headername);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		if (!config_check_cond(srv, con, dc)) continue;

                /* Got matching context, enter the given values */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
                        /* if the option was set in this context, use it */
                        if (USED("rpaf.enable")) PATCH(enabled);
                        if (USED("rpaf.proxy_ips")) PATCH(proxy_ips);
                        if (USED("rpaf.sethostname")) PATCH(sethostname);
                        if (USED("rpaf.header")) PATCH(headername);
                }
	}

	return 0;
}
#undef USED
#undef PATCH

static int is_in_array(const char *remote_ip, array *proxy_ips) {
    for (size_t i = 0; i < proxy_ips->used; i++) {
        data_string *ds = (data_string *)proxy_ips->data[i];
        if ( strcmp(remote_ip, ds->value->ptr)==0 )
            return 1;
    }
    return 0;
}

static const char* get_header_value(array* headers, const char* key) {
    data_string *ds = (data_string*)array_get_element(headers,key);
    return ds?ds->value->ptr:NULL;
}

static void set_host_header(array* headers, const char *value) {
    array_set_key_value(headers, "Host", 4, value, strlen(value));
}

URIHANDLER_FUNC(mod_rpaf_uri_handler) {
	plugin_data *p = p_d;

	UNUSED(srv);
	
	mod_rpaf_patch_connection(srv, con, p);

        // continue processing if disabled or IP is'nt in IP list
        if( !p->conf.enabled || !is_in_array((const char*)inet_ntop_cache_get_ip(srv, &con->dst_addr),p->conf.proxy_ips) )
            return HANDLER_GO_ON;

        const char *fwdvalue = NULL;

        /* check if conf.headername is set and if it is use
           that instead of X-Forwarded-For by default */
        if( p->conf.headername->ptr && (fwdvalue=get_header_value(con->request.headers, p->conf.headername->ptr)) ) {
            // use conf.headername
        } else if ( (fwdvalue=get_header_value(con->request.headers, "X-Forwarded-For")) ) {
            // use "X-Forwarded-For"
        } else {
            log_error_write(srv, __FILE__, __LINE__, "s",
                "Can\'t find header:\"X-Forwarded-For\" (or use custom header: rpaf.header = \"X-Real-IP\") with external IP");
            return HANDLER_GO_ON;
        }

        // handle current request?
        if( fwdvalue ) {
            // replace external source addr
            buffer_copy_string(con->dst_addr_buf, fwdvalue);
            con->dst_addr.ipv4.sin_addr.s_addr = inet_addr(con->dst_addr_buf->ptr);

            // need to update host name?
            if( p->conf.sethostname ) {
                const char *hostvalue;
                if( ( hostvalue=get_header_value(con->request.headers, "X-Forwarded-Host") ) ||
                    ( hostvalue=get_header_value(con->request.headers, "X-Host") ) ) {
                    //
                    set_host_header(con->request.headers, hostvalue);
                    buffer_copy_string(con->uri.authority, hostvalue);
                } else {
                    log_error_write(srv, __FILE__, __LINE__, "s",
                        "Can\'t find header\'s:(\"X-Forwarded-Host\"|\"X-Host\") (disable feature: rpaf.sethostname = 0 or set required header)");
                }
            }
        }

	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */
int mod_rpaf_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("rpaf");
	
	p->init        = mod_rpaf_init;
	p->handle_uri_clean  = mod_rpaf_uri_handler;
	p->set_defaults  = mod_rpaf_set_defaults;
	p->cleanup     = mod_rpaf_free;

	p->data        = NULL;

	return 0;
}
