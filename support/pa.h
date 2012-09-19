#define RECSTART "@£$1"
#define RECSTOP "@£$0"
#define ENDOFLINE "@£$2"

#define RECSIZE 2048
#define NRECORDS 8

#define IN 1
#define OUT 2
#define ERR 3

#ifndef PA_INTERNAL
extern char recording[NRECORDS][RECSIZE];
char regex_group[NRECORDS][RECSIZE];
extern char *DOCUMENT_URI, *HTTPS;
char *QUERY_STRING;
extern int get, post, head, put, http, https, protocol;
#endif

/*
 * Dump env
 */
int dump(const char *filename);

/*
 * msg: Log message
 */
int _msg( const char *message, ...);
#define msg(MSG, A...) _msg(MSG, ##A, NULL)

/*
 * concatenate strings
 */
char *_concat(const char *s, ...);
#define concat(STR, A...) _concat(STR, ##A, NULL)

/*
 * true if useragent_ip match
 */
int useragent_ip(const char *ip);

/*
 * true if useragent_ip match net
 */
int useragent_net(const char *net);

/*
 * true if useragent hostname matches
 */
int useragent_host(const char *host);

/*
 * Query hostname DNS-format.
 * Example: host("www.aaa.bb")
 */
int host(const char *hostname);

/*
 * Return true if the path component of the URI equals 'path'.
 */
int path(const char *path);

/*
 * Return true if the path component of the URI begins with 'path'.
 */
int path_prefix(const char *path);
  
/*
 * Path matching.
 * If arg matches the search (and path position) advances to the next arg.
 * If an arg does not match the next arg is tried against the same position in path.
 * The last arg MUST match.
 * If the last arg matches the function returns true.
 * If arg is RECSTART then everything that matches in path is stored in the global variable recording[n], until RECSTOP.
 *  The index [n] is increased with every encounter of RECSTART.
 *
 * Example: path_match("/", "dir/", RECSTART, "favicon.ico", RECSTOP))
 */
int _path_match( const char *noop, ...);
#define path_match(A...) _path_match(NULL, ##A, NULL)

/*
 * Generic regexp
 * Matching groups are store din regex_group[]
 */
int regex(const char *buffer, const char *expr);

/*
 * Regexp match of path component of the URI.
 */
int path_regex(const char *expr);

/*
 * Set document root for request
 */
int document_root(const char *path);

/*
 * The hostname to send for a proxy-request.
 */
int proxy_host(const char *hostname);

/*
 * Reverse proxy translation
 */
int proxy_reverse(const char *real, const char *fake);

/*
 * Path to balancer filesystem storage
 */
int balancer_storage(const char *path);

/*
 * Define a balancer backend
 */
int backend(const char *set, const char *uri);

/*
 * Select a backend from a set
 */
const char *backend_select(const char *set);

/*
 * Fail a backend
 */
int backend_fail(const char *set, const char *uri);

/*
 * Redirect client
 */
int _redirect_to(const char *URI, ...);
#define redirect_to(URI, A...) _redirect_to(URI, ##A, NULL)

/*
 * Serve specific file
 */
int _serve_file(const char *filepath, ...);
#define serve_file(filepath, A...) _serve_file(filepath, ##A, NULL)

/*
 * Execute specific CGI
 */
int _exec_cgi(const char *cgipath, ...);
#define exec_cgi(filepath, A...) _exec_cgi(filepath, ##A, NULL)

/*
 * Set timeout
 */
int timeout(int t);

/*
 * set incoming host header and switch vhost
 */
int _change_vhost(const char *hostname, ...);
#define change_vhost(hostname, A...) _change_vhost(hostname, ##A, NULL)

/*
 * add output filter named 'filtername' to request
 */
int add_filter(const char *filtername);

/*
 * return HTTP status NNN to client
 */
int return_status(int status);

/*
 * replace occurances of <real> with <fake> within the output document
 */
int substitute_text(const char *real, const char *fake);

/*
 * set handler to 'handler'
 */
int set_handler(const char *handler);

/*
 * export variable to CGI
 */
int _export_var(const char *name, const char *value, ...);
#define export_var(name, value, A...) _export_var(name, value, ##A, NULL)

/*
 * set HTTP query string to 'S'
 */
int _set_query_string(const char *value, ...);
#define set_query_string(value, A...) _set_query_string(value, ##A, NULL)

/*
 * PATH_INFO=PATH   -- set PATH_INFO for CGI. 
 */
int _set_path_info(const char *value, ...);
#define set_path_info(value, A...) _set_path_info(value, ##A, NULL)

/*
 * set header named 'name' to 'value'
 * type = IN|OUT|ERR
 */
int _set_header(int type, const char *name, const char *value, ...);
#define set_header(type, name, value, A...) _set_header(type, name, value, ##A, NULL)

/*
 * Compare value of cookie named 'name' with value.
 */
int _cookie(const char *name, ...);
#define cookie(name, A...) _cookie(name, ##A, NULL)

/*
 * Compare value of query_string field
 * The empty string matches field that is present but without a value
 */
int _query_field(const char *field, ...);
#define query_field(field, A...) _query_field(field, ##A, NULL)

/*
 * We are done processing and return to the request handling.
 */
void done();

void debug();

void _rf_init();
