/*
 * File: support/pa.c
 * Implements: support functions for programmable configuration

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
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <pcre.h>

#define RF_INTERNAL
#include "pa.h"

char recording[NRECORDS][RECSIZE];
char regex_group[NRECORDS][RECSIZE];
char *DOCUMENT_URI;
char *ORIG_DOCUMENT_URI;
char *USERAGENT_IP;
int USERAGENT_AF = AF_INET;
char *HTTPS;
char *QUERY_STRING;
int get, post, head, put, http, https, protocol;

static int _rf_debug;

struct backend {
	const char *uri;
	const char *filename;
	struct backend *next;
};

struct backend_set {
	int n;
	const char *name;
	struct backend *backends;
	struct backend_set *next;
};

static const char *_rf_balance_dir = "/tmp";

struct {
	struct backend_set *backend_sets;
} _rf;

static void errout()
{
	_exit(1);
}

static const char *_va_buf(va_list *ap)
{
        const char *p;
	char *buf;
        size_t bufsize = 1024;
	buf = malloc(bufsize);
        if(!buf) errout();
        *buf = 0;
	while( (p=va_arg(*ap, char *)) ) {
                if(strlen(buf) + strlen(p) >= bufsize) {
                        bufsize*=2;
                        buf = realloc(buf, bufsize);
                        if(!buf) errout();
                }
                strcat(buf, p);
        }
	return buf;
}

static char *concat2(const char *s1, const char *s2)
{
	char *s;
	s = malloc(strlen(s1)+strlen(s2)+1);
	if(s) {
		strcpy(s, s1);
		strcpy(s+strlen(s1), s2);
		return s;
	}
	errout();
	return "";
}

static char *_substr(const char *s, int len)
{
	char *n;

	n = malloc(len+1);
	strncpy(n, s, len);
	n[len] = 0;
	return n;
}

static char *gethdr(const char *name)
{
	char *p;
	char buf[128];
	
	snprintf(buf, sizeof(buf), "IN::%s", name);
	p = getenv(buf);
	if(!p) {
		snprintf(buf, sizeof(buf), "IN__%s", name);
		p = getenv(buf);
	}
	return p;
}

/*
 * Query hostname DNS-format.
 * Example: host("www.aaa.bb")
 */
int host(const char *hostname)
{
	char *u = gethdr("Host");
	if(!u) return 0;
	
	if(_rf_debug) fprintf(stderr, "host() strcmp(\"%s\", \"%s\") == %d\n", hostname, u, strcmp(hostname, u));
	return strcmp(hostname, u)==0;
}

/*
 * Return true if the path component of the URI equals 'path'.
 */
int path(const char *path)
{
	char *u = DOCUMENT_URI;
	if(!u) return 0;
	if(_rf_debug) fprintf(stderr, "path() strcmp(\"%s\", \"%s\") == %d\n", path, u, strcmp(path, u));
	return strcmp(path, u)==0;
}

/*
 * Return true if the path component of the URI begins with 'path'.
 * If the prefix matches the rest of the DOCUMENT_URI is placed in recording[0].
 */
int path_prefix(const char *path)
{
	char *u = DOCUMENT_URI;
	if(!u) return 0;
	if(_rf_debug) fprintf(stderr, "path_prefix() strncmp(\"%s\", \"%s\", %zd) == %d\n", path, u, strlen(path), strncmp(path, u, strlen(path)));
        if(strncmp(path, u, strlen(path)))
		return 0;
	strncpy(recording[0], u + strlen(path), RECSIZE-1);
	recording[0][RECSIZE-1]=0;
	return 1;
}

/*
 * Path matching.
 * If arg matches the search (and path position) advances to the next arg.
 * If an arg does not match the next arg is tried against the same position in path.
 * The last arg MUST match.
 * If the last arg matches the function returns true.
 * If arg is RECSTART then everything that matches in path is stored in the global variable recording[n], until RECSTOP.
 *  The index [n] is increased with every encounter of RECSTART.
 *
 * Example: path_match("/", "dir/", RECSTART, "favicon.ico", RECSTOP, ENDOFLINE))
 */
int _path_match( const char *noop, ...)
{
	const char *pe, *nextpe, *path;
	int last = 0;
	int rec = -1;
	int rec_on = 0;
	int cmpstatus = 1;
	va_list ap;
	
	path = DOCUMENT_URI;
	if(!path) return 0;

	va_start(ap, noop);
	
	pe = va_arg(ap, char *);

	while(pe) {
		if(strcmp(pe, RECSTART)==0) {
			if((rec+1) < NRECORDS) {
				rec++;
				if(_rf_debug) fprintf(stderr, "path_match() RECSTART %d\n", rec);
				rec_on=1;
				recording[0][0] = 0;
			} else {
				if(_rf_debug) fprintf(stderr, "path_match() RECSTART declined\n");
			}
			pe = va_arg(ap, char *);
		}
		if(strcmp(pe, RECSTOP)==0) {
			rec_on=0;
			if(_rf_debug) fprintf(stderr, "path_match() RECSTOP %d\n", rec);
			if(_rf_debug) fprintf(stderr, "path_match() recording[%d] = \"%s\"\n", rec, recording[rec]);
			pe = va_arg(ap, char *);
			if(!pe) {
				va_end(ap);
				return cmpstatus;				
			}
		}
		nextpe = va_arg(ap, char *);
		if(nextpe == NULL)
			last = 1;
		if(strcmp(pe, ENDOFLINE)==0) {
			if(*path)
				cmpstatus = 0;
			else
				cmpstatus = 1;
		} else {
			if(_rf_debug) fprintf(stderr, "path_match() strncmp(\"%s\", \"%s\", %zd) == %d\n",
					      path, pe, strlen(pe), strncmp(path, pe, strlen(pe)));
			if(strncmp(path, pe, strlen(pe))==0) {
				cmpstatus=1;
				path += strlen(pe);
				if(rec_on) {
					if(strlen(pe) + strlen(recording[rec]) < RECSIZE)
						strcat(recording[rec], pe);
					else
						strncat(recording[rec], pe, RECSIZE - strlen(recording[rec]) - 1);
					if(last) {
						if(strlen(path) + strlen(recording[rec]) < RECSIZE)
							strcat(recording[rec], path);
						else
							strncat(recording[rec], path, RECSIZE - strlen(recording[rec]) - 1);     
					}
				}
			} else
				cmpstatus=0;
		}
		if(cmpstatus == 0) {
			if(last) {
				va_end(ap);
				return 0;
			}
		}
		pe = nextpe;
	}
	
	va_end(ap);
	if(_rf_debug && rec_on) fprintf(stderr, "path_match() recording[%d] = \"%s\"\n", rec, recording[rec]);
	return 1;
}

/*
 * Generic regexp
 * Matching groups are store din regex_group[]
 */
int regex(const char *buffer, const char *expr)
{
	pcre *patt;
	int errcode;
	int rc, i;
	int ovector[30];
	
	if(_rf_debug) fprintf(stderr, "regex() compile(\"%s\")\n", expr);
	patt = pcre_compile2(expr,
			     0, /* options: PCRE_ANCHORED PCRE_CASELESS  */
			     &errcode,
			     NULL, NULL,
			     NULL);
	if(!patt) {
		if(_rf_debug) fprintf(stderr, "regex() compile failed: %d\n", errcode);
		return 0;
	}

	rc = pcre_exec(
		patt,             /* result of pcre_compile() */
		NULL,           /* we didn't study the pattern */
		buffer,  /* the subject string */
		strlen(buffer),             /* the length of the subject string */
		0,              /* start at offset 0 in the subject */
		0,              /* default options */
		ovector,        /* vector of integers for substring information */
		30);            /* number of elements (NOT size in bytes) */
	if(_rf_debug) fprintf(stderr, "regex() pcre_exec() == %d\n", rc);	

	if(rc < 0) return 0;
	
	for(i=0;i<rc;i++) {
		int len;
		len = ovector[ (i << 1) + 1 ] - ovector[ (i << 1) ];
		if(len >= RECSIZE) len = RECSIZE-1;
		strncpy(regex_group[i], buffer + ovector[ (i << 1) ], len);
		regex_group[i][len] = 0;
		if(_rf_debug) fprintf(stderr, "regex() regex_group[%d] = \"%s\"\n", i, regex_group[i]);	
	}
	return rc+1;
}

/*
 * Regexp match of path component of the URI.
 */
int path_regex(const char *expr)
{
	char *u = DOCUMENT_URI;
	if(!u) return 0;
	return regex(u, expr);
}

/*
 * The hostname to send for a proxy-request.
 */
int proxy_host(const char *hostname)
{
	printf("Proxy-host=%s\n", hostname);
	return 0;
}


/*
 * Reverse proxy translation
 */
int proxy_reverse(const char *real, const char *fake)
{
	printf("Proxy-reverse-alias=%s,%s\n", real, fake);
	return 0;
}

struct backend_set *_rf_backend_set(const char *name)
{
	struct backend_set *set;
	for(set = _rf.backend_sets; set; set = set->next) {
		if(strcmp(set->name, name)==0)
			return set;
	}
	return NULL;
}

static char *_rf_mkfilename(const char *uri)
{
	char *buf, *p;

	buf = malloc(strlen(uri)*3 + strlen(_rf_balance_dir) + 2);
	strcpy(buf, _rf_balance_dir);
	p = buf + strlen(_rf_balance_dir);
	*p++ = '/';
	for(;*uri;uri++) {
		if(*uri == '/') {
			*p++ = '%';
			*p++ = '2';
			*p++ = 'f';
			uri++;
		} else {
			*p++ = *uri++;
		}
	}
	return buf;
}

/*
 * Define a balancer backend
 */
int backend(const char *name, const char *uri)
{
	struct backend_set *set;
	struct backend *be;

	set = _rf_backend_set(name);
	if(!set) {
		set = malloc(sizeof(struct backend_set));
		if(set) {
			set->n = 0;
			set->name = name;
			set->next = _rf.backend_sets;
			_rf.backend_sets = set;
			if(_rf_debug) fprintf(stderr, "backend() created set \"%s\"\n", name);
		} else {
			return -1;
		}
	}

	be = malloc(sizeof(struct backend));
	if(be) {
		be->uri = uri;
		be->filename = _rf_mkfilename(uri);
		be->next = set->backends;
		set->backends = be;
		set->n++;
		if(_rf_debug) fprintf(stderr, "backend() backend defined \"%s\"\n", uri);
		return 0;
	}

	return -1;
}

static unsigned int _rf_client_hash()
{
	char *u = USERAGENT_IP;
	unsigned int h = 0;
	if(!u) return 0;
	
	while(*u) h += *u++;
	return h;
}

static int _rf_backend_failed(struct backend *be)
{
	struct stat statb;
	return stat(concat2(be->filename, ".failed"), &statb) == 0;
}

/*
 * Path to balancer filesystem storage
 */
int balancer_storage(const char *path)
{
	/*
	 * FIXME: verify that storage is writable?
	 */
	_rf_balance_dir = path;
	if(_rf_debug) fprintf(stderr, "balancer_storage() set to \"%s\"\n", path);
	return 0;
}

/*
 * Select a backend from a set
 */
const char *backend_select(const char *name)
{
	struct backend_set *set;
	struct backend *be, *prev;
	unsigned int h = _rf_client_hash();
	int n;
	
	set = _rf_backend_set(name);
	if(!set) errout();
	
	while(1) {
		n = h % set->n;
		be=set->backends;
		prev=NULL;
		for(;n;n--) {
			prev = be;
			be=be->next;
		}
		
		if(!be) errout();
		
		if(!_rf_backend_failed(be)) {
			if(_rf_debug) fprintf(stderr, "backend_select(\"%s\") selected: \"%s\"\n", name, be->uri);
			return be->uri;
		}
		if(_rf_debug) fprintf(stderr, "backend_select(\"%s\") skipping: \"%s\"\n", name, be->uri);
		
		set->n--;
		if(prev) {
			prev->next = be->next;
		} else {
			set->backends = be->next;
		}
	}
	
	errout();
	return "";
}

static struct backend *_rf_backend(struct backend_set *set, const char *uri)
{
	struct backend *be;
	for(be=set->backends;be;be=be->next)
		if(!strcmp(be->uri, uri))
			return be;
	return NULL;
}

/*
 * Fail a backend
 */
int backend_fail(const char *name, const char *uri)
{
	struct backend_set *set;
	struct backend *be;
	int fd;
	char *fn;

	set = _rf_backend_set(name);
	be = _rf_backend(set, uri);

	fn = concat2(be->filename, ".failed");
	fd = open(fn, O_CREAT, 0660);
	if(fd >= 0) {
		if(_rf_debug) fprintf(stderr, "backend_fail(\"%s\", \"%s\") done.\n", name, be->uri);
		close(fd);
	} else {
		if(_rf_debug) fprintf(stderr, "backend_fail(\"%s\", \"%s\") error.\n", name, be->uri);
	}
	return 0;
}

/*
 * Activate a failed backend
 */
int backend_unfail(const char *name, const char *uri)
{
	struct backend_set *set;
	struct backend *be;
	char *fn;

	set = _rf_backend_set(name);
	be = _rf_backend(set, uri);

	fn = concat2(be->filename, ".failed");
	if(unlink(fn)) {
		if(_rf_debug) fprintf(stderr, "backend_unfail(\"%s\", \"%s\") done.\n", name, be->uri);
	}
	return 0;
}

/*
 * Redirect client
 */
int _redirect_to(const char *URI, ...)
{
	const char *p;
	va_list ap;
	char *buf;
	size_t bufsize = 1024;

	buf = malloc(bufsize);
	if(!buf) errout();
	*buf = 0;
	
	va_start(ap, URI);
	while( (p=va_arg(ap, char *)) ) {
		if(strlen(buf) + strlen(p) >= bufsize) {
			bufsize*=2;
			buf = realloc(buf, bufsize);
			if(!buf) errout();
		}
		strcat(buf, p);
	}
	va_end(ap);
	
	printf("Redirect=%s%s\n", URI, buf);
	
	return 0;
}

/*
 * Serve specific file
 */
int _serve_file(const char *filepath, ...)
{
	va_list ap;
	va_start(ap, filepath);
	printf("Filename=%s%s\n", filepath, _va_buf(&ap));
	va_end(ap);
	return 0;
}

/*
 * Execute specific CGI
 */
int _exec_cgi(const char *cgipath, ...)
{
        va_list ap;
        va_start(ap, cgipath);
        printf("CGI=%s%s\n", cgipath, _va_buf(&ap));
        va_end(ap);
        return 0;
}

/*
 * set incoming host header and switch vhost
 */
int _change_vhost(const char *hostname, ...)
{
	va_list ap;
        va_start(ap, hostname);
        printf("IN::Host=%s%s\n", hostname, _va_buf(&ap));
        va_end(ap);
        return 0;
}

/*
 * add output filter named 'filtername' to request
 */
int add_filter(const char *filtername)
{
        printf("Filter=%s\n", filtername);
        return 0;
}

/*
 * return HTTP status NNN to client
 */
int return_status(int status)
{
	printf("Status=%d\n", status);
	return 0;
}

/*
 * replace occurances of <real> with <fake> within the output document
 */
int substitute_text(const char *real, const char *fake)
{
	printf("Substitute=%s,%s\n", real, fake);
	return 0;
}

/*
 * set handler to 'handler'
 */
int set_handler(const char *handler)
{
	printf("Handler=%s\n", handler);
	return 0;
}

/*
 * Set document root for request
 */
int document_root(const char *path)
{
	printf("DocumentRoot=%s\n", path);
	return 0;
}

/*
 * export variable to CGI
 */
int _export_var(const char *name, const char *value, ...)
{
	va_list ap;
	va_start(ap, value);
        printf("Export=%s=%s%s\n", name, value, _va_buf(&ap));
        va_end(ap);
        return 0;
}

/*
 * set HTTP query string to 'S'
 */
int _set_query_string(const char *value, ...)
{
	va_list ap;
	va_start(ap, value);
	printf("QUERY_STRING=%s%s\n",value, _va_buf(&ap));
	va_end(ap);
	return 0;
}


/*
 * PATH_INFO=PATH   -- set PATH_INFO for CGI. 
 */
int _set_path_info(const char *value, ...)
{
        va_list ap;
        va_start(ap, value);
        printf("PATH_INFO=%s%s\n",value, _va_buf(&ap));
        va_end(ap);
        return 0;
}


/*
 * set header named 'name' to 'value'
 * type = IN|OUT|ERR
 */
int _set_header(int type, const char *name, const char *value, ...)
{
	char *typestr = "OUT";
        va_list ap;
	if(type == IN) typestr = "IN";
	if(type == ERR) typestr = "ERR";
        va_start(ap, value);
        printf("%s::%s=%s%s\n", typestr, name, value, _va_buf(&ap));
        va_end(ap);
        return 0;
}

/*
 * Compare value of cookie named 'name' with 'value'.
 */
int _cookie(const char *name, ...)
{
	const char *s;
	char *p;
	char *desc, *cookie;
        va_list ap;

	desc = malloc(strlen(name)+4);
	sprintf(desc, "%s=", name);

	va_start(ap, name);

	s = _va_buf(&ap);
	va_end(ap);

	if(_rf_debug) fprintf(stderr, "cookie(\"%s\", \"%s\")\n" , name, s);

	cookie = gethdr("Cookie");
	if(!cookie) return 0;

	if(strncmp(cookie, desc, strlen(desc))) {
		sprintf(desc, "; %s=", name);
		p = strstr(cookie, desc);
		if(!p) {
			sprintf(desc, ";%s=", name);
			p = strstr(cookie, desc);
		}
	} else {
		p = cookie;
	}
	if(!p) return 0;

	cookie = p + strlen(desc);

	if(strncmp(cookie, s, strlen(s))) {
		if(_rf_debug) fprintf(stderr, "cookie: \"%s\" != \"%s\"\n" , _substr(cookie, strlen(s)), s);
		return 0;
	}
	
	cookie += strlen(s);
	if(*cookie && *cookie != ';') {
		if(_rf_debug) fprintf(stderr, "cookie: '%c' at end of value\n" , *cookie);
		return 0;
	}
	
	return 1;
}


/*
 * Compare value of query_string field
 * The empty string matches field that is present but without a value
 */
int _query_field(const char *field, ...)
{
	const char *value;
	char *p;
	char *desc;
        va_list ap;

	va_start(ap, field);
	value = _va_buf(&ap);
	va_end(ap);

	desc = malloc(strlen(field)+4);
	if(*value) {
		sprintf(desc, "%s=", field);
	} else {
		sprintf(desc, "%s", field);
	}
	
	if(_rf_debug) fprintf(stderr, "query_field(\"%s\", \"%s\")\n" , field, value);

	if(strncmp(QUERY_STRING, desc, strlen(desc))) {
		if(*value) {
			sprintf(desc, "&%s=", field);
		} else {
			sprintf(desc, "&%s&", field);
		}
		p = strstr(QUERY_STRING, desc);
		if(p && !value) goto matched;
		
		if(!value && !p) {
			sprintf(desc, "&%s", field);
		        p = strstr(QUERY_STRING + strlen(QUERY_STRING) - strlen(field), field);
			if(p) goto matched;
		}
	} else {
		p = QUERY_STRING;
	}
	if(!p) return 0;
	
	p+=strlen(desc);

	if(*value) {
		if(strncmp(p, value, strlen(value))) {
			if(_rf_debug) fprintf(stderr, "query_field: \"%s\" != \"%s\"\n" , _substr(p, strlen(value)), value);
			return 0;
		}
		
		p += strlen(value);
	}
	
	if(*p && *p != '&') {
		if(_rf_debug) fprintf(stderr, "query_field: '%c' at end of value\n" , *p);
		return 0;
	}
	
matched:
	if(_rf_debug) fprintf(stderr, "query_field(\"%s\", \"%s\") == 1 (matched)\n" , field, value);
	return 1;	
}


int timeout(int t)
{
	printf("Timeout=%d\n", t);
	return 0;
}

void _init()
{
	char *method, *proto;
	DOCUMENT_URI = getenv("DOCUMENT_URI");
	if(!DOCUMENT_URI) DOCUMENT_URI="/";
	ORIG_DOCUMENT_URI = strdup(DOCUMENT_URI);
	USERAGENT_IP = getenv("useragent_ip");
	HTTPS = getenv("HTTPS");
	QUERY_STRING = getenv("QUERY_STRING");
	method = getenv("method");
	proto = getenv("protocol");
	if(proto && strlen(proto) > 2) {
		protocol = (*proto - '0') * 10;
		protocol += *(proto+2) - '0';
	} else protocol = 10;
	if(method) {
		if(!strcmp(method, "POST")) post=1;
		if(!strcmp(method, "HEAD")) head=1;
		if(!strcmp(method, "PUT")) put=1;
	}
	if(post+head+put == 0) get=1;
	if(!QUERY_STRING) QUERY_STRING="";
	if(!USERAGENT_IP) USERAGENT_IP="";
	if(USERAGENT_IP) {
		if(strchr(USERAGENT_IP, ':')) USERAGENT_AF = AF_INET6;
	}
}

static int printenv(int fd, const char *env)
{
	char *p;
	p = getenv(env);
	if(write(fd, env, strlen(env)) == -1) return -1;
	if(p) {
		if(write(fd, "=", 1) == -1) return -1;
		if(write(fd, p, strlen(p)) == -1) return -1;
	}
	if(write(fd, "\n", 1) == -1) return -1;
	return 0;
}

/*
 * Dump env
 */
int dump(const char *fn)
{
	int fd;
	fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(fd < 0) return -1;
	
	if(printenv(fd, "DOCUMENT_URI")) goto out;
	if(printenv(fd, "IN::Host")) goto out;
	if(printenv(fd, "QUERY_STRING")) goto out;
	if(printenv(fd, "method")) goto out;
	if(printenv(fd, "protocol")) goto out;
	if(printenv(fd, "servername")) goto out;
	if(printenv(fd, "useragent_ip")) goto out;
	if(printenv(fd, "HTTPS")) goto out;
	printenv(fd, "local_ip");
out:
	close(fd);
	return 0;
}

/*
 * msg: Log message
 */
int _msg(const char *message, ...)
{
	const char *m;
        va_list ap;

	va_start(ap, message);
	m = _va_buf(&ap);
	va_end(ap);

	printf("Log=%s%s\n", message, m);
	return 0;
}

char *_concat(const char *s, ...)
{
	const char *m;
	va_list ap;

        va_start(ap, s);
        m = _va_buf(&ap);
        va_end(ap);

	n = malloc(strlen(s) + strlen(m) +1);
	strcpy(n, s);
	strcat(n, m);
	return n;
}

/*
 * true if useragent_ip match net
 */
int useragent_net(const char *net)
{
        int plen, i;
        int af = AF_INET;
        char *p;
        unsigned char *u;
        unsigned char mask[16];
        unsigned char buf[16];
        unsigned char ip[16];
        net = strdup(net);

        if(strchr(net, ':')) af = AF_INET6;
        if(af != USERAGENT_AF) return 0;

        if( (p=strchr(net, '/')) ) {
                plen = atoi(p+1);
                *p = 0;
        } else {
                plen = af == AF_INET6 ? 128:32;
        }

        if(inet_pton(af, net, buf)!=1) return 0;
        if(inet_pton(af, USERAGENT_IP, ip)) return 0;

        memset(mask, 0, sizeof(mask));
        for(u=mask,i=0;i<(plen>>3);i++) {
                *u++ = 0xff;
        }
        plen -= (plen & ~7);

        if(plen) {
                for(i=7;i>=(8-plen);i--) {
                        *u |= (1<<i);
                }
        }
        for(i=0;i<(af==AF_INET?4:16);i++) {
                if((ip[i] & mask[i]) != (buf[i] & mask[i])) return 0;
	}

        return 1;
}


/*
 * true if useragent_ip match
 */
int useragent_ip(const char *ip)
{
	return useragent_net(ip);
}

/*
 * true if useragent hostname matches
 */
int useragent_host(const char *host)
{
	const struct sockaddr *sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	socklen_t salen;
	unsigned char ip[16];
	char ua[512];

	if(inet_pton(USERAGENT_AF, USERAGENT_IP, ip)!=1)
		return 0;
	if(USERAGENT_AF == AF_INET) {
		memset(&in,0,sizeof(in));
		memcpy(&in.sin_addr.s_addr, ip, 4);
		in.sin_family = AF_INET;
		sa = &in;
		salen = sizeof(in);
	} else {
		memset(&in6,0,sizeof(in6));
		memcpy(&in6.sin6_addr.s6_addr, ip, 16);
		in6.sin6_family = AF_INET6;
		sa = &in6;
		salen = sizeof(in6);
	}

	if(getnameinfo(sa, salen,
		       ua, sizeof(ua),
		       NULL, 0, NI_NAMEREQD))
		return 0;
	return strcasecmp(host, ua)==0;
}


/*
 * We are done processing and return to the request handling.
 */
void done()
{
	if(strcmp(DOCUMENT_URI, ORIG_DOCUMENT_URI))
		printf("DOCUMENT_URI=%s\n", DOCUMENT_URI);
	fflush(stdout);
	_exit(0);
}

void debug()
{
	_rf_debug = 1;
}
