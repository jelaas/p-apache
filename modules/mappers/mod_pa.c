/*
 * File: mod_pa.c
 * Implements: programmable configuration module

   Copyright Jens L��s, 2012

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_vhost.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include "apr_strings.h"

#include <stdio.h>

typedef struct pa_cfg {
	const char *prg;
	const char *err_prg;
	int loglevel;
} pa_cfg;

module AP_MODULE_DECLARE_DATA pa_module;

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *pa_is_https = NULL;

static void *pa_create_server_config(apr_pool_t *p, server_rec *s)
{
    pa_cfg *cfg;

    if(!pa_is_https)
	    pa_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    cfg = (pa_cfg *) apr_pcalloc(p, sizeof(pa_cfg));
    cfg->loglevel = APLOG_WARNING;
    return (void *) cfg;
}

static apr_status_t pa_close_file(void *vfile)
{
	return apr_file_close(vfile);
}

static apr_proc_t *pa_ext_child(apr_pool_t *p, const char *progname, const char **envp, int noout)
{
	apr_status_t rc;
	apr_procattr_t *procattr;
	apr_proc_t *procnew;
	if (((rc = apr_procattr_create(&procattr, p)) == APR_SUCCESS)
	    && ((rc = apr_procattr_cmdtype_set(procattr, APR_PROGRAM)) == APR_SUCCESS)
	    && ((rc = apr_procattr_io_set(procattr,
					  APR_NO_PIPE,
					  noout?APR_NO_PIPE:APR_FULL_BLOCK,
					  APR_NO_PIPE)) == APR_SUCCESS)
                ) {
		char **args;
		const char *pname;
		apr_tokenize_to_argv(progname, &args, p);
		pname = apr_pstrdup(p, args[0]);
		procnew = (apr_proc_t *)apr_pcalloc(p, sizeof(*procnew));

		rc = apr_proc_create(procnew, pname, (const char * const *)args,
				     envp, procattr, p);
		if (rc == APR_SUCCESS) {
			apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
			if(!noout) {
				apr_pool_cleanup_register(p, procnew->out,
							  apr_pool_cleanup_null,
							  pa_close_file);
			}
			return procnew;
		}
	}

	return NULL;
}

static const char **pa_make_env(request_rec *r)
{
	const char **envp;
	apr_array_header_t *envarr;
	int i;

	envarr = apr_array_make (r->pool, 0, sizeof(char*));
	
	/* copy headers_in into array */
	{
		const apr_array_header_t *tarr = apr_table_elts(r->headers_in);
		const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
		
		for (i = 0; i < tarr->nelts; i++) {
			*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool,
									    "IN::",
									    telts[i].key,
									    "=",
									    telts[i].val,
									    NULL);
		}
		
	}
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "DOCUMENT_URI=", r->uri, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "QUERY_STRING=", r->args, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "method=", r->method, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "protocol=", r->protocol, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "servername=", ap_get_server_name(r), NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool,
							    "useragent_ip=",
							    r->useragent_ip, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool,
							    "client_ip=",
							    r->connection->client_ip, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "local_ip=", r->connection->local_ip, NULL);
	if(pa_is_https && pa_is_https(r->connection))
		*(const char**)apr_array_push(envarr) = "HTTPS=on";
	
	/* create envp. size of array */
	envp = apr_pcalloc(r->pool, sizeof(char*) * (envarr->nelts + 1));
	
	/* assign array elements */
	for (i = 0; i < envarr->nelts; i++) {
		envp[i] = ((const char**)envarr->elts)[i];
	}

	return envp;
}

static const char **pa_make_err_env(request_rec *r)
{
	const char **envp;
	apr_array_header_t *envarr;
	int i;
	const char *proxy;

	envarr = apr_array_make (r->pool, 0, sizeof(char*));
	
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "DOCUMENT_URI=", r->uri, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "FILENAME=", r->filename, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "QUERY_STRING=", r->args, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "method=", r->method, NULL);
	*(const char**)apr_array_push(envarr) = apr_psprintf(r->pool, "status=%d", r->status);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "protocol=", r->protocol, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "servername=", ap_get_server_name(r), NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool,
							    "useragent_ip=",
							    r->useragent_ip, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool,
							    "client_ip=",
							    r->connection->client_ip, NULL);
	*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "local_ip=", r->connection->local_ip, NULL);

	if(pa_is_https && pa_is_https(r->connection))
		*(const char**)apr_array_push(envarr) = "HTTPS=on";

	*(const char**)apr_array_push(envarr) = "PAERROR=1";

	proxy = apr_table_get(r->notes, "proxy-host");
	if(proxy)
		*(const char**)apr_array_push(envarr) = apr_pstrcat(r->pool, "PROXY_HOST=", proxy, NULL);
	
	/* create envp. size of array */
	envp = apr_pcalloc(r->pool, sizeof(char*) * (envarr->nelts + 1));
	
	/* assign array elements */
	for (i = 0; i < envarr->nelts; i++) {
		envp[i] = ((const char**)envarr->elts)[i];
	}

	return envp;
}

static int pa_translate(request_rec *r)
{
	pa_cfg *cfg;
	char *filename, *cgi, *docroot;

	cfg = ap_get_module_config(r->server->module_config, &pa_module);
	if(!cfg->prg) return DECLINED;
	
	docroot = (char*) apr_table_get(r->notes, "req-docroot");

	filename = (char*) apr_table_get(r->notes, "req-filename");
	if(filename) {
		r->filename = filename;
		
		if(cfg->loglevel >= APLOG_DEBUG) 
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: filename set to %s", filename);
		return OK;
	}
	cgi = (char*) apr_table_get(r->notes, "req-cgi");
	if(cgi) {
		char *pathinfo;
		
		r->filename = cgi;
		r->handler = "cgi-script";
		if(cfg->loglevel >= APLOG_DEBUG) 
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: cgi to run %s", cgi);

		pathinfo = (char*) apr_table_get(r->notes, "req-pathinfo");
		if(pathinfo) {
			r->path_info = pathinfo;
			r->used_path_info = AP_REQ_ACCEPT_PATH_INFO;
			if(cfg->loglevel >= APLOG_DEBUG) 
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
					     "pa: req-pathinfo set \"%s\"", pathinfo);
		}
		apr_table_setn(r->notes, "alias-forced-type", r->handler);
		return OK;
	}
	return DECLINED;
}

static int pa_post_read_request(request_rec *r)
{
	pa_cfg *cfg;
	char *uri = NULL;
	char *filename = NULL;
	char *cgi = NULL;
	char *location = NULL;
	char *status = NULL;
	char *pathinfo = NULL;
	char *hostname = NULL;
	
	cfg = ap_get_module_config(r->server->module_config, &pa_module);

	if(!cfg->prg) return DECLINED;

	/* create and execute child program
	   see server/log.c for howto run a child process */
	{
		apr_proc_t *proc;
		int st;
		apr_exit_why_e why;
		apr_status_t rv;
		const char **envp;
		char *p;
		int hlen;
		
		envp = pa_make_env(r);
	    
		if(cfg->loglevel >= APLOG_DEBUG) 
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "pa: prg \"%s\"", cfg->prg);
		proc = pa_ext_child(r->pool, cfg->prg, envp, 0);
		if(!proc) {
			if(cfg->loglevel >= APLOG_ERR)
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
					     "pa: failed to run prg \"%s\"", cfg->prg);
		}
		if(proc) {
			while (1) {
				char buf[4096];
				
				/* read the command's output through the pipe */
				rv = apr_file_gets(buf, sizeof(buf), proc->out);
				if (APR_STATUS_IS_EOF(rv)) {
					if(cfg->loglevel >= APLOG_DEBUG)
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: read EOF");
					break;
				}
				
				if(cfg->loglevel >= APLOG_DEBUG)
					ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: read \"%s\"", buf);
				if((p=strchr(buf, '='))) {
					hlen = p - buf;
				} else {
					continue;
				}
				
				{
					int i;
					i = strlen(buf);
					if(buf[i-1] == '\n')
						buf[i-1] = 0;
				}
				
				if(strncmp(buf, "Log=", 4)==0) {
					ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: log \"%s\"", buf+4);
					continue;
				}
				
				if(strncmp(buf, "DOCUMENT_URI=", 13)==0) {
					uri = apr_pstrcat(r->pool, buf+13, NULL);
					if(cfg->loglevel >= APLOG_DEBUG) 
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
							     "pa: uri set \"%s\"", uri);
					continue;
				}
				if(strncmp(buf, "Proxy-reverse-alias=", 20)==0) {
					if(strchr(buf, ',')) {
						char *alias;
						alias = apr_pstrcat(r->pool, buf+20, NULL);
						apr_table_add(r->notes, "proxy-ralias", alias);
						if(cfg->loglevel >= APLOG_DEBUG) 
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
								     "pa: ralias added \"%s\"", alias);
					}
					continue;
				}
				if(strncmp(buf, "Substitute=", 11)==0) {
					if(strchr(buf, ',')) {
						char *alias;
						alias = apr_pstrcat(r->pool, buf+11, NULL);
						apr_table_add(r->notes, "pa-sed", alias);
						if(cfg->loglevel >= APLOG_DEBUG) 
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
								     "pa: sed-filter added \"%s\"", alias);
					}
					continue;
				}
				if(strncmp(buf, "Filter=", 7)==0) {
					if(strchr(buf, ',')) {
						char *alias;
						alias = apr_pstrcat(r->pool, buf+7, NULL);
						apr_table_add(r->notes, "pa-filter", alias);
						if(cfg->loglevel >= APLOG_DEBUG) 
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
								     "pa: filter added \"%s\"", alias);
					}
					continue;
				}
				if(strncmp(buf, "Proxy-host=", 11)==0) {
					char *phost;
					phost = apr_pstrcat(r->pool, buf+11, NULL);
					apr_table_set(r->notes, "proxy-host", phost);
					if(cfg->loglevel >= APLOG_DEBUG) 
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
							     "pa: proxy-host set \"%s\"", phost);
					continue;
				}
				
				if(strncmp(buf, "Redirect=", 9)==0) {
					location = apr_pstrdup( r->pool, buf+9 );
					continue;
				}
				if(strncmp(buf, "PATH_INFO=", 10)==0) {
					pathinfo = apr_pstrdup( r->pool, buf+10 );
					continue;
				}
				
				if(strncmp(buf, "Status=", 7)==0) {
					status = apr_pstrdup( r->pool, buf+7 );
					continue;
				}
				
				if(strncmp(buf, "Filename=", 9)==0) {
					filename = apr_pstrdup( r->pool, buf+9 );
					continue;
				}
				if(strncmp(buf, "DocumentRoot=", 13)==0) {
					apr_table_set(r->notes, "req-docroot", apr_pstrcat(r->pool, buf+13, NULL));
					continue;
				}
				
				if(strncmp(buf, "Handler=", 8)==0) {
					r->handler = apr_pstrdup( r->pool, buf+8 );
					continue;
				}
				
				if(strncmp(buf, "CGI=", 4)==0) {
					cgi = apr_pstrdup( r->pool, buf+4 );
					continue;
				}
				
				if(strncmp(buf, "Export=", 7)==0) {
					char *val;
					apr_table_t *e = r->subprocess_env;
					val = strchr(buf+7, '=');
					if(val) {
						apr_table_setn(e, 
							       apr_pstrndup( r->pool, buf+7, val-(buf+7)),
							       apr_pstrdup(r->pool, val+1));
					} else {
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
							     "pa: Export without value \"%s\"", buf+7);
					}
				}
				
				/* replace args */
				if(strncmp(buf, "QUERY_STRING=", 13)==0) {
					r->args = apr_pstrcat(r->pool, buf+13, NULL);
					if(cfg->loglevel >= APLOG_DEBUG) 
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
							     "pa: args set \"%s\"", r->args);
					continue;
				}
				
				if(hlen > 5) {
					if(strncmp(buf, "OUT::", 5)==0) {
						char *hname;
						hname = apr_pstrndup( r->pool, buf+5, hlen-5);
						apr_table_set(r->headers_out, hname, buf+hlen+1);
						if(cfg->loglevel >= APLOG_DEBUG) 
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
								     "pa: headers_out %s set \"%s\"", hname, buf+hlen+1);
						continue;
					}
				}
				
				if(hlen > 5) {
					if(strncmp(buf, "ERR::", 5)==0) {
						char *hname;
						hname = apr_pstrndup( r->pool, buf+5, hlen-5);
						apr_table_set(r->err_headers_out, hname, buf+hlen+1);
						if(cfg->loglevel >= APLOG_DEBUG) 
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
								     "pa: err_headers_out %s set \"%s\"", hname, buf+hlen+1);
						continue;
					}
				}
				
				if(hlen > 4) {
					if(strncmp(buf, "IN::", 4)==0) {
						char *hname;
						hname = apr_pstrndup( r->pool, buf+4, hlen-4);
						apr_table_set(r->headers_in, hname, buf+hlen+1);
						if(strncmp(buf, "IN::Host", 8)==0)
							hostname = apr_pstrdup( r->pool, buf+hlen+1);
						if(cfg->loglevel >= APLOG_DEBUG) 
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
								     "pa: headers_in %s set \"%s\"", hname, buf+hlen+1);
						continue;
					}
				}
			}
			
			apr_file_close(proc->out);
			
			rv = apr_proc_wait(proc, &st, &why, APR_WAIT);
			if( !(why & APR_PROC_EXIT) ) {
				if(why & APR_PROC_SIGNAL)
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
						     "pa: prg killed by signal!");			
				if(why & APR_PROC_SIGNAL_CORE)
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
						     "pa: prg killed and core-dumped!");			
			} else {
				if( (st != APR_ENOTIMPL) && st) {
					if(cfg->loglevel >= APLOG_WARNING)
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
						     "pa: child done: exit status = %d", st);		
				}
			}
		}
	}
	
	/* did we switch vhost? */
	if(hostname) {
		r->hostname = hostname;
		ap_update_vhost_from_headers(r);
		r->per_dir_config = r->server->lookup_defaults;
		if(cfg->loglevel >= APLOG_DEBUG) 
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: vhost change to %s", hostname);
	}
	
	/* redirect this via proxy module */
	
	if(status) {
		int n;
		n = atoi(status);
		if( (n >= 100) && (n < 600)) {
			return n;
		}
		if(cfg->loglevel >= APLOG_ERR) { 
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "pa: Illegal status code: %d", n);
		}
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	if(location) {
		apr_table_set(r->headers_out, "Location", location);
		if(cfg->loglevel >= APLOG_DEBUG) 
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: redirect to %s", location);
		return HTTP_MOVED_TEMPORARILY;
	}
	
	/* set proxy: and handler */
	if(uri) {
		if(*uri == '/') {
			/* rewrite local URL */
			if(cfg->loglevel >= APLOG_DEBUG) 
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: rewrite local uri to %s", uri);
			r->uri = uri;
		} else {
			r->handler  = "proxy-server";
			r->proxyreq = PROXYREQ_REVERSE;
			r->filename = apr_pstrcat(r->pool, "proxy:", uri, NULL);
			if(cfg->loglevel >= APLOG_DEBUG) 
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "pa: proxy to %s", r->filename);
		}
	}
	if(filename) {
		/* pass filename to later translate hook */
		apr_table_set(r->notes, "req-filename", filename);
	}
	if(cgi) {
		apr_table_set(r->notes, "req-cgi", cgi);
	}
	if(pathinfo) {
		apr_table_set(r->notes, "req-pathinfo", pathinfo);
	}
	
	return DECLINED;
}

static const char *pa_cmd(cmd_parms *parms, void *dummy, const char *arg)
{
	apr_finfo_t finfo;
	
	pa_cfg *cfg = ap_get_module_config(parms->server->module_config, &pa_module);

	if(*arg != '/') {
		return "mod_pa: Not an absolute path!";
	}

	/* does file exist? */
	if(apr_stat(&finfo,
		    arg,
		    APR_FINFO_PROT,
		    parms->pool) !=  APR_SUCCESS ) {
		return "mod_pa: File does not exist";
	}
	/* can we excute it? */
	if(!(finfo.protection & (APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE))) {
		return "mod_pa: Cannot execute file";
	}
	
	cfg->prg = arg;

	return NULL;
}

static const char *pa_cmd_err(cmd_parms *parms, void *dummy, const char *arg)
{
	apr_finfo_t finfo;
	
	pa_cfg *cfg = ap_get_module_config(parms->server->module_config, &pa_module);

	if(*arg != '/') {
		return "mod_pa: Not an absolute path!";
	}

	/* does file exist? */
	if(apr_stat(&finfo,
		    arg,
		    APR_FINFO_PROT,
		    parms->pool) !=  APR_SUCCESS ) {
		return "mod_pa: File does not exist";
	}
	/* can we excute it? */
	if(!(finfo.protection & (APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE))) {
		return "mod_pa: Cannot execute file";
	}
	
	cfg->err_prg = arg;

	return NULL;
}

static const char *pa_cmd_log(cmd_parms *parms, void *dummy, const char *arg)
{
	pa_cfg *cfg = ap_get_module_config(parms->server->module_config, &pa_module);

	if(!apr_strnatcasecmp(arg, "DEBUG")) {
		cfg->loglevel = APLOG_DEBUG;
		return NULL;
	}
	if(!apr_strnatcasecmp(arg, "INFO")) {
		cfg->loglevel = APLOG_INFO;
		return NULL;
	}
	if(!apr_strnatcasecmp(arg, "NOTICE")) {
		cfg->loglevel = APLOG_NOTICE;
		return NULL;
	}
	if(!apr_strnatcasecmp(arg, "WARNING")) {
		cfg->loglevel = APLOG_WARNING;
		return NULL;
	}
	if(!apr_strnatcasecmp(arg, "ERROR")) {
		cfg->loglevel = APLOG_ERR;
		return NULL;
	}
	if(!apr_strnatcasecmp(arg, "ERR")) {
		cfg->loglevel = APLOG_ERR;
		return NULL;
	}

	return "Unknown loglevel";
}

static int pa_logger(request_rec *r)
{
	pa_cfg *cfg;
	
	if(r->status < 500) return DECLINED;

	cfg = ap_get_module_config(r->server->module_config, &pa_module);

	if(!cfg->err_prg) return DECLINED;

	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "pa: logger: status = %d", r->status);

	{
		apr_proc_t *proc;
		int st;
		apr_exit_why_e why;
		apr_status_t rv;
		const char **envp;
		
		envp = pa_make_err_env(r);
		
		if(cfg->loglevel >= APLOG_DEBUG) 
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "pa: prg \"%s\"", cfg->err_prg);
		proc = pa_ext_child(r->pool, cfg->err_prg, envp, 1);
		if(!proc) {
			if(cfg->loglevel >= APLOG_ERR)
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
					     "pa: failed to run prg \"%s\"", cfg->err_prg);
		}
		if(proc) {
			rv = apr_proc_wait(proc, &st, &why, APR_WAIT);
			if( !(why & APR_PROC_EXIT) ) {
				if(why & APR_PROC_SIGNAL)
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
						     "pa: prg killed by signal!");			
				if(why & APR_PROC_SIGNAL_CORE)
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
						     "pa: prg killed and core-dumped!");			
			} else {
				if( (st != APR_ENOTIMPL) && st) {
					if(cfg->loglevel >= APLOG_WARNING)
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
						     "pa: child done: exit status = %d", st);		
				}
			}
		}
	}
	
	return DECLINED;
}

struct pa_sed_filter_def {
	apr_table_t *defs;
	int use;
};

/*
 * search for table keys in buf.
 * return pointer to first table_key found
 * return key and target in real and fake
 */
static const char *findreal(const char **real, const char **fake, const char *buf, apr_table_t *sed)
{
	int i;
	const char *p, *best = NULL;
	const apr_array_header_t *tarr = apr_table_elts(sed);
	const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
		
	for (i = 0; i < tarr->nelts; i++) {
		p = strstr(buf, telts[i].key);
		if(!p) continue;
		if(!best) {
			best = p;
			*real = telts[i].key;
			*fake = telts[i].val;
		}
		if(p < best) {
			best = p;
			*real = telts[i].key;
			*fake = telts[i].val;
		}
	}
	return best;
}


/* https://httpd.apache.org/docs/2.3/developer/output-filters.html */
static apr_status_t pa_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	apr_bucket *b = APR_BRIGADE_FIRST(bb);
	struct pa_sed_filter_def *ctx;

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "pa: in filter = %s", f->r->content_type);	

	/* fast exit */
	if (APR_BRIGADE_EMPTY(bb)) {
		//return ap_pass_brigade(f->next, bb);
	        return APR_SUCCESS;
	}

	if(!(ctx = f->ctx))
		return ap_pass_brigade(f->next, bb);
	
	if(!ctx->use) {
		if(!f->r->content_type)
			return ap_pass_brigade(f->next, bb);
		if(f->r->content_type && strncmp(f->r->content_type, "text/html", 9)) {
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}
	}
	ctx->use = 1;
	
	apr_table_unset(f->r->headers_out, "Content-Length");
	
	/* FIXME: correct this to use temporary brigade to not consume memory (atleast on local file reads)
	 * see: https://httpd.apache.org/docs/2.3/developer/output-filters.html
	 */
	for ( b = APR_BRIGADE_FIRST(bb);
	      b != APR_BRIGADE_SENTINEL(bb);
	      b = APR_BUCKET_NEXT(b) ) {
		const char* buf;
		size_t bytes;
		if ( APR_BUCKET_IS_EOS(b) ) {
			;
		} else if ( apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ)
			    == APR_SUCCESS ) {
			/* We have a bucket full of text.  Just escape it where necessary */
			size_t count = 0;
			const char* p = buf;
			const char *t;
			
			while ( count < bytes ) {
				size_t sz = 0;
				size_t slen;
				const char *real, *fake;
				t = findreal(&real, &fake, p, ctx->defs);
				if(!t) break;
				slen = strlen(real);
				
				sz = t-p;
				count += sz ;
				
				if ( count < bytes ) {
					apr_bucket_split(b, sz);
					b = APR_BUCKET_NEXT(b);
					APR_BUCKET_INSERT_BEFORE(b,
								 apr_bucket_transient_create(fake, strlen(fake),
											     f->r->connection->bucket_alloc));
					apr_bucket_split(b, slen);
					APR_BUCKET_REMOVE(b);
					b = APR_BUCKET_NEXT(b);
					count += 1;
					p += sz + slen;
				}
			}
		}
	}
	return ap_pass_brigade(f->next, bb) ;
}

static ap_filter_rec_t * pa_filter_rec;

static void pa_insert_filter(request_rec *r) {
	pa_cfg *cfg;
	const char *fdefs, *p;
	struct pa_sed_filter_def *ctx = NULL;
	
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "pa: sed-filter = %s", r->content_type);	

	cfg = ap_get_module_config(r->server->module_config, &pa_module);

	if(!cfg->prg) return;

	/*
	 * looks like content_type is not yet set for proxied requests, nor cgis.
	 * might be because we set handler directly
	 * probably we need to detect this from "inside" the filter
	 */

	if(r->content_type && strncmp(r->content_type, "text/html", 9)) {
		return;
	}
	
	fdefs = (char*) apr_table_get(r->notes, "pa-filter");
	if(fdefs) {
		/* adding filter by name (without context..) */
		ap_add_output_filter(fdefs, NULL, r, r->connection);
	}

	{
		const apr_array_header_t *tarr = apr_table_elts(r->notes);
		const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
		int i;
		
		for (i = 0; i < tarr->nelts; i++) {
			if(strcmp(telts[i].key, "pa-sed"))
				continue;
			fdefs = telts[i].val;
			if(!fdefs) continue;
			
			p = strchr(fdefs, ',');
			if(!p) continue;
			if(!ctx) {
				ctx = apr_palloc(r->pool, sizeof(*ctx));
				ctx->defs = apr_table_make(r->pool, 10); 
				ctx->use = 0;				
			}
			apr_table_set( ctx->defs,
				       apr_pstrndup( r->pool, fdefs, p-fdefs), /* real */
				       apr_pstrdup( r->pool, p+1) /* fake */
				);
		}
	}
	if(ctx)
		ap_add_output_filter_handle(pa_filter_rec, ctx, r, r->connection);
}

static void pa_register_hooks(apr_pool_t *p)
{
	ap_hook_insert_filter(pa_insert_filter, NULL, NULL, APR_HOOK_MIDDLE) ;
	ap_hook_post_read_request(pa_post_read_request, NULL, NULL,
				  APR_HOOK_MIDDLE);
	ap_hook_translate_name(pa_translate, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_log_transaction(pa_logger, NULL, NULL, APR_HOOK_MIDDLE);
	pa_filter_rec = ap_register_output_filter("pa-output-filter", pa_filter,
						  NULL, AP_FTYPE_RESOURCE);
}

static const command_rec pa_cmds[] =
{
    AP_INIT_TAKE1("PAConfig",
		  pa_cmd,
		  NULL,
		  RSRC_CONF,
		  "Configure external configuration program"),
    AP_INIT_TAKE1("PAError",
		  pa_cmd_err,
		  NULL,
		  RSRC_CONF,
		  "Configure external program for error reporting"),
    AP_INIT_TAKE1("PALogLevel",
		  pa_cmd_log,
		  NULL,
		  RSRC_CONF,
		  "Configure PA-module log level"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA pa_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    pa_create_server_config, /* server config creator */
    NULL, /* extconfig_merge_server_config,  server config merger */
    pa_cmds,                 /* command table */
    pa_register_hooks,       /* set up other request processing hooks */
};
