/*
   Copyright 2013 Jason Fesler

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


/* This module reports the IP the user came from, as a JSONP response. GET requests required; CGI style arguments are permitted.
 * callback=[name]     to call a function name of your choosing size=[number]       to bad the http data portion of the response.
 * (Does not attempt to offset header response) If the callback is "?", it will output to the screen (calling it "callback"). Any
 * other, and a JSON mime type is used instead. */


/* NOTICE
 * 
 * Portions of this module are inspired by: "The Apache Modules Book: Application Development with Apache"  by Nick Kew; published by
 * Prentice Hall, January 27 2007.
 * 
 */

/* Changes:
 * 
 * 2013-04-29 - jfesler@gigo.com
 *              Add headers to output (content type, expires, cache control)
 *              Stop depending on mod_headers (and user config)
 * 
 * 2013-04-28 - jfesler@gigo.com
 *              Add built in definitions for 6to4 and Teredo
 *              Seperate the function that adds new prefixes, from the config parser/hook
 *              Made ./configure friendly
 *
 * 2013-04-14 - jfesler@gigo.com
 *            - ASN queries also populate a string with the entire list of ASNs
 *
 * 2013-03-23 - jfesler@gigo.com
 *            - ASN queries always compiled in.  Triggers on asn=1 in request arguments.
 *            - ALWAYS_PADDING now full time.
 *            - Conditional compiling directives removed.  Troublesome across platforms.
 *
 * 2013-01-25 - eric@vyncke.org
 *	      - conditional compile for ASN related DNS queries
 *	      - also report asn_name
 *
 * 2012-12-26 - eric@vyncke.org
 *            - also return the ASN number (to be used to detect tunnels by the client) code from mysasn.code.google.com
 *
 * 2011-02-07 -  ondrej.sury@nic.cz
 *            - use apache (per request) memory pools and not static buffers 
 *            - drop my_strtok (now thread safe code) 
 *            - optimize parse_form_from_string 
 *            - rewrite output function 
 *            - limit maximum padding size to 1600 (see the #define) 
 *            - always add padding="" if compiled with -DALWAYS_PADDING 
 *            - limit the maximum length of callback function name to 64 (#define) 
 *            - some more micro optimizations to make code less nested, etc. 
 *            - limit callback name characters (security)
 * 
 * 2011-02-20 - jfesler@gigo.com 
 *            - new parameter: testip=  (40 chars or less; alphanum) for testing purposes 
 *            - prefixes are now parsed  on startup; and do cidr notation. 
 *            - http "Via" lines are now reported.
 *
 * 2011-02-27 - jfesler@gigo.com - use config file instead.  mod_ip_prefix 2002::/16 "6to4"
 *            - Also, disabled proxy reporting; just returns empty string or 'yes' now.  Suspect in core dumps.
 * 
 * 2011-04-19 - ondrej@sury.org - Generate size buffer on-the-fly, not in the buffer
 *
 * 2011-05-02 - ondrej@sury.org - Move MAX_PADDING_SIZE to config file (mod_ip_max_padding)
 *
 */



#include <ctype.h>
#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_network_io.h>

/* Those unfortunately look like they claim the autoconf variables, so let's undefine them */

#undef PACKAGE_VERSION
#undef PACKAGE_URL
#undef PACKAGE_STRING
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_TARNAME

/* We need some libraries besides what Apache provides. */

#include "config.h"



#define MAX_PADDING_SIZE 64*1024*1024
#define MAX_CALLBACK_SIZE 64
#define MAX_TESTIP_SIZE 40
#define MAX_PREFIXES 500

#define PADDING_BUFFER_SIZE 4096
#define PADDING_DEFAULT_SIZE 1600

const char *padding_buffer = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gQWxpcXVhbSBzb2RhbGVzIHVsdHJpY2llcyBlZ2VzdGFzLiBOdWxsYW0gYWNjdW1zYW4gdGluY2lkdW50IG1hc3NhLCBpZCB2ZXN0aWJ1bHVtIHB1cnVzIHNvZGFsZXMgY29uZ3VlLiBJbiBpZCBpYWN1bGlzIGF1Z3VlLiBEb25lYyBhdCBpcHN1bSBtYXNzYSwgcXVpcyBmcmluZ2lsbGEgYW50ZS4gTnVsbGFtIHJ1dHJ1bSwgZHVpIGZldWdpYXQgY29uZGltZW50dW0gbGFvcmVldCwgdXJuYSBhcmN1IHBvcnRhIGVzdCwgZXQgY29uZ3VlIHNhcGllbiBsZWN0dXMgcXVpcyBtYXVyaXMuIENyYXMgbmVjIHNlbSB2ZWxpdCwgdm9sdXRwYXQgbWF0dGlzIG1hc3NhLiBDcmFzIGZldWdpYXQgZHVpIHNjZWxlcmlzcXVlIGFudGUgYXVjdG9yIGF0IGZyaW5naWxsYSBzYXBpZW4gaGVuZHJlcml0LiBTZWQgaGVuZHJlcml0IG5pc2wgdml0YWUgbmlzaSBjb21tb2RvIGlkIGZhY2lsaXNpcyB1cm5hIGltcGVyZGlldC4gSW50ZWdlciBlc3QgZmVsaXMsIGxhY2luaWEgaWQgYWRpcGlzY2luZyBub24sIGVsZWlmZW5kIGlkIG5lcXVlLiBNYXVyaXMgZ3JhdmlkYSB2ZWxpdCBxdWlzIHNhcGllbiBzb2RhbGVzIGluIGlhY3VsaXMgZWxpdCBwbGFjZXJhdC4gUGhhc2VsbHVzIGhlbmRyZXJpdCBlcm9zIHJpc3VzLCBxdWlzIHVsdHJpY2llcyBsYWN1cy4gUXVpc3F1ZSBmYWNpbGlzaXMgYWxpcXVhbSBhdWd1ZSB2aXRhZSB2b2x1dHBhdC4gTmFtIHNpdCBhbWV0IGxvcmVtIGluIGxhY3VzIHBoYXJldHJhIHRlbXBvciBzZWQgZWdldCBudWxsYS4gTnVuYyBsb2JvcnRpcyB0aW5jaWR1bnQgbmlzbCBldSBldWlzbW9kLiBJbiBoYWMgaGFiaXRhc3NlIHBsYXRlYSBkaWN0dW1zdC4KCk51bGxhbSBuZWMgZW5pbSBhYyBwdXJ1cyBvcm5hcmUgc2NlbGVyaXNxdWUgZWdldCBzaXQgYW1ldCBzZW0uIERvbmVjIG1vbGxpcyBqdXN0byB2ZWwgbnVuYyBkaWN0dW0gY3Vyc3VzLiBDdXJhYml0dXIgdml2ZXJyYSBwb3N1ZXJlIGNvbnZhbGxpcy4gVmVzdGlidWx1bSB2dWxwdXRhdGUgc2FnaXR0aXMgc3VzY2lwaXQuIFF1aXNxdWUgdmVsIG51bmMgYSBzZW0gdm9sdXRwYXQgcG9ydGEuIEludGVnZXIgaW4gbWkgZWdldCBhbnRlIGx1Y3R1cyBzY2VsZXJpc3F1ZSBpZCBpbiBsZW8uIE1vcmJpIGNvbnNlcXVhdCBkaWduaXNzaW0gdmVoaWN1bGEuIFF1aXNxdWUgbWF0dGlzIGVsZW1lbnR1bSBkaWFtIHZpdGFlIGxvYm9ydGlzLiBOdWxsYSBldSBmYXVjaWJ1cyBvZGlvLiBNb3JiaSB2ZW5lbmF0aXMgc29kYWxlcyBlbmltLCBzaXQgYW1ldCBzdXNjaXBpdCBvcmNpIGFsaXF1ZXQgdmVsLiBJbnRlZ2VyIGVsZW1lbnR1bSBkaWFtIGV0IG51bGxhIGxhY2luaWEgc3VzY2lwaXQuIERvbmVjIGxlY3R1cyBhdWd1ZSwgbG9ib3J0aXMgYWxpcXVldCBldWlzbW9kIGV0LCBlZ2VzdGFzIGluIG5lcXVlLiBWZXN0aWJ1bHVtIGV1IGxvcmVtIHRlbGx1cy4gRXRpYW0gZGlnbmlzc2ltIHBvc3VlcmUgbGFjdXMgcXVpcyB1bHRyaWNlcy4KClV0IGVsZWlmZW5kIGNvbnNlY3RldHVyIHR1cnBpcyBzaXQgYW1ldCB2dWxwdXRhdGUuIFF1aXNxdWUgZXUgbWFzc2EgYXQgYW50ZSBhdWN0b3IgYmxhbmRpdCB2aXRhZSBxdWlzIGxlby4gTW9yYmkgYSByaXN1cyB2aXRhZSBzZW0gbW9sZXN0aWUgcnV0cnVtIG5vbiBuZWMgbGlndWxhLiBQZWxsZW50ZXNxdWUgZXQgbGFvcmVldCBuZXF1ZS4gU2VkIGJsYW5kaXQgY29uc2VxdWF0IHJob25jdXMuIE51bGxhIGZhY2lsaXNpLiBNYXVyaXMgZWdldCBsZWN0dXMgdml0YWUgc2FwaWVuIHNlbXBlciB0cmlzdGlxdWUuIE51bmMgYXVjdG9yIGVsaXQgYXQgc2FwaWVuIHRpbmNpZHVudCBxdWlzIGZlcm1lbnR1bSBsaWd1bGEgcGxhY2VyYXQuIEZ1c2NlIGJpYmVuZHVtIGxvcmVtIGlkIG1pIGxhY2luaWEgaWQgY3Vyc3VzIG9kaW8gZGljdHVtLiBWaXZhbXVzIGVsaXQgb3JjaSwgcHVsdmluYXIgdmVsIGFjY3Vtc2FuIGV0LCBhbGlxdWFtIGF0IGFyY3UuIEN1cmFiaXR1ciBmYWNpbGlzaXMgZWdlc3RhcyBkaWFtLCBub24gc29sbGljaXR1ZGluIHZlbGl0IGFsaXF1YW0gdml0YWUuIERvbmVjIGxhY2luaWEsIG5pc2wgYSBpbnRlcmR1bSBlbGVpZmVuZCwgdmVsaXQgbmliaCBoZW5kcmVyaXQgaXBzdW0sIGFjIGFjY3Vtc2FuIGF1Z3VlIGVyYXQgdmVsIHNhcGllbi4gTWF1cmlzIHNlZCBuaXNpIHF1aXMgYW50ZSBwcmV0aXVtIGRpY3R1bS4gSW50ZWdlciBldCBsZWN0dXMgYXQgbGVvIGludGVyZHVtIHNvZGFsZXMgZWdldCBub24gdmVsaXQuCgpVdCBpZCBzYXBpZW4gYXQgbG9yZW0gZmV1Z2lhdCB1bHRyaWNpZXMgZGljdHVtIGFkaXBpc2Npbmcgb2Rpby4gVmVzdGlidWx1bSBsYWNpbmlhIGVyb3MgcXVpcyBuaXNpIG1vbGxpcyB2ZWhpY3VsYS4gVmVzdGlidWx1bSBhbnRlIGlwc3VtIHByaW1pcyBpbiBmYXVjaWJ1cyBvcmNpIGx1Y3R1cyBldCB1bHRyaWNlcyBwb3N1ZXJlIGN1YmlsaWEgQ3VyYWU7IEZ1c2NlIGNvbnNlcXVhdCwgZXN0IG5lYyB2dWxwdXRhdGUgaW50ZXJkdW0sIGVzdCBuaWJoIHBvcnRhIHNlbSwgdXQgcGhhcmV0cmEgYW50ZSBsb3JlbSBldCBsaWJlcm8uIFF1aXNxdWUgdmVzdGlidWx1bSBtYXVyaXMgbm9uIGZlbGlzIGVsZWlmZW5kIHBlbGxlbnRlc3F1ZS4gRnVzY2UgdHJpc3RpcXVlIGp1c3RvIHNpdCBhbWV0IGxlY3R1cyBpbXBlcmRpZXQgbG9ib3J0aXMuIFZlc3RpYnVsdW0gbGVjdHVzIHF1YW0sIGdyYXZpZGEgc2VkIGZlcm1lbnR1bSBuZWMsIGNvbnNlcXVhdCBlZ2V0IHF1YW0uIEN1bSBzb2NpaXMgbmF0b3F1ZSBwZW5hdGlidXMgZXQgbWFnbmlzIGRpcyBwYXJ0dXJpZW50IG1vbnRlcywgbmFzY2V0dXIgcmlkaWN1bHVzIG11cy4gTnVsbGEgZmFjaWxpc2kuIEluIGNvbnNlcXVhdCBibGFuZGl0IHRlbGx1cyB1dCBzb2xsZXQgbmV0dXMgZXQgbWFsZXN1YWRhIGZhbWVzIGFjIHR1cnBpcyBlZ2VzdGFzLgoKRHVpcyBiaWJlbmR1bSBpbXBlcmRpZXQgbGliZXJvIHZlbCBwb3J0YS4gUXVpc3F1ZSBub24gbmVxdWUgc2VkIHF1YW0gdWxsYW1jb3JwZXIgZnJpbmdpbGxhLiBQcm9pbiBmZWxpcyBtYXVyaXMsIGFjY3Vt";

#define DELIM "&;"

#define ASNLIST_LENGTH 64

#if AP_SERVER_MAJORVERSION_NUMBER > 2 || \
    (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
#define CLIENT_IP(request) ((request)->useragent_ip)
#else
#define CLIENT_IP(request) ((request)->connection->remote_ip)
#endif

typedef struct mod_ip_request_t
{
	apr_int64_t size;
	apr_byte_t getasn;
	char *callback;
	char *testip;
} mod_ip_request_t;


typedef struct mod_ip_prefixes_t
{
	apr_ipsubnet_t *ip;
	char *provider;
	void *next;
} mod_ip_prefixes_t;

mod_ip_prefixes_t *mod_ip_prefix_head = NULL;



typedef struct
{
	apr_ipsubnet_t *cidr;
	char *info;
} cidrinfo_type;

typedef struct
{
	apr_array_header_t *cidrinfo;
	apr_int64_t max_padding;
} mod_ip_svr_cfg;


static void *mod_ip_create_svr_conf (apr_pool_t * pool, char *x);
static void *mod_ip_merge_svr_conf (apr_pool_t * pool, void *BASE, void *ADD);
static void mod_ip_hooks (apr_pool_t * pool);
static const char *mod_ip_config_subnet (cmd_parms * cmd, void *CFG, const char *arg1, const char *arg2);
static const char *mod_ip_max_padding(cmd_parms * cmd, void *CFG, const char *arg);
module AP_MODULE_DECLARE_DATA mod_ip_module;


/* Parse form data from a string. The input string is NOT preserved. */
static mod_ip_request_t *
parse_form_from_string (request_rec * r, char *args, mod_ip_request_t * formdata)
{
	char *pair;
	char *eq;
	char *last = NULL;
	mod_ip_svr_cfg *cfg = ap_get_module_config (r->server->module_config, &mod_ip_module);

	/* Sanity check */
	if (formdata == NULL) {
		return NULL;
	}
	/* Defaults */
	formdata->size = 0;
	formdata->callback = NULL;
	formdata->testip = NULL;

	/* No arguments?  No parsing! */
	if (args == NULL) {
		return formdata;
	}
	/* Split the input on '&' */
	for (pair = apr_strtok (args, DELIM, &last); pair != NULL; pair = apr_strtok (NULL, DELIM, &last)) {

		/* Unescape '+' to ' ' */
		for (eq = pair; *eq; ++eq) {
			if (*eq == '+') {
				*eq = ' ';
			}
		}

		if (strncmp (pair, "size=", 5) == 0) {
			formdata->size = apr_atoi64 (pair + 5);
			if (formdata->size > cfg->max_padding) {
				ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_ERR, 0,
					      r, "[mod_ip.c] size: `%lld' >= max_padding_size `%d'", (long long) formdata->size,
					      MAX_PADDING_SIZE);
				return NULL;
			}
		} else if (strncmp (pair, "asn=", 4) == 0) {
			formdata->getasn = (apr_atoi64 (pair + 4) > 0);
		} else if (strncmp (pair, "callback=", 9) == 0) {
			if (strlen (pair + 9) > MAX_CALLBACK_SIZE) {
				/* Max function name length */
				ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_ERR, 0,
					       r,
					       "[mod_ip.c] function name length: `%s' (`%zu') >= max_callback_size `%d'",
					       pair + 9, strlen (pair + 9), MAX_CALLBACK_SIZE);
				return NULL;
			}
			ap_unescape_url (pair + 9);
			ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_DEBUG, 0, r, "[mod_ip.c] checking function name: `%s'",
				       pair + 9);
			if (strcmp (pair + 9, "?") != 0) {	/* If callback=? then use plain_text */
				for (eq = pair + 9; *eq; ++eq) {
					if (!isalnum (*eq) && (*eq != '_')) {
						/* Callback function name violation */
						ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_ERR, 0,
							       r, "[mod_ip.c] function name: `%s' violates naming convention: `%c'",
							       pair + 9, *eq);
					}
				}
				formdata->callback = apr_pstrdup (r->pool, (const char *) pair + 9);
			}
		} else if (strncmp (pair, "testip=", 7) == 0) {
			if (strlen (pair + 7) > MAX_TESTIP_SIZE) {
				ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_ERR, 0,
					       r,
					       "[mod_ip.c] function name length: `%s' (`%zu') >= max_callback_size `%d'",
					       pair + 9, strlen (pair + 9), MAX_CALLBACK_SIZE);
				return NULL;

			}
			for (eq = pair + 7; *eq; ++eq) {
				if (!isalnum (*eq) && (*eq != ':') && (*eq != '.')) {
					/* Callback function name violation */
					ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_ERR, 0,
						       r, "[mod_ip.c] testip value: `%s' violates naming convention: `%c'",
						       pair + 7, *eq);
					return NULL;
				}
			}
			formdata->testip = apr_pstrdup (r->pool, (const char *) pair + 7);
		}
	}

	return formdata;
}

static mod_ip_request_t *
parse_form_from_GET (request_rec * r, mod_ip_request_t * formdata)
{
	return parse_form_from_string (r, r->args, formdata);
}



static char    *
escape_string(request_rec * r, char *str)
{
	char           *newstr = NULL;
	char           *source = NULL;
	char           *dest = NULL;
	char           *maxdest = NULL;
	int		l;

	if (str == NULL) {
		return "";
	}
	/* We might potentially escape EVERY character.  Worst case. */
	l = strlen(str);
	newstr = apr_palloc(r->pool, l * 2 + 2);

	source = str;
	dest = newstr;
	maxdest = newstr + l * 2;

	while ((*source) && (dest < maxdest)) {
		switch (*source) {
		case '"':
			*(dest++) = '\\';
			*(dest++) = '\"';
			source++;
			break;
		case '\r':
			*(dest++) = '\\';
			*(dest++) = 'r';
			source++;
			break;
		case '\n':
			*(dest++) = '\\';
			*(dest++) = 'n';
			source++;
			break;
		case '\b':
			*(dest++) = '\\';
			*(dest++) = 'b';
			source++;
			break;
		default:
			*(dest++) = *(source++);
		}
	}
	*dest = '\0';
	return newstr;
}

char *
mod_ip_find_info (request_rec * r, char *myip)
{
	int i = 0;
	apr_array_header_t *arr;
	mod_ip_svr_cfg *cfg = ap_get_module_config (r->server->module_config, &mod_ip_module);
	apr_sockaddr_t *sockaddr = NULL;
	apr_status_t rv;
	cidrinfo_type *cidrinfo = NULL;
	apr_ipsubnet_t *cidr;
	char *info;
	 

	if ((cfg) && (cfg->cidrinfo) && ((rv = apr_sockaddr_info_get (&sockaddr, myip, AF_INET6, 0, 0, r->pool)) == APR_SUCCESS)) {
		arr = cfg->cidrinfo;  /* apr_array_header_t */
/*                cidrinfo = (cidrinfo_type**) arr->elts;*/
		for (i = 0; i < arr->nelts; i++) {

                       
		       cidrinfo = &((cidrinfo_type*) arr->elts)[i];
		       cidr = cidrinfo->cidr;
		       info = cidrinfo->info;
		       
			if (apr_ipsubnet_test (cidr, sockaddr)) {
				return info;
			}
		}
	}

	return "";
}

void
gen_output (request_rec * r, struct mod_ip_request_t *formdata)
{
	size_t output_len;
	char *padding = ",\"padding\":\"";
	char *p = NULL;
	int added = 0;
	char *myip = CLIENT_IP(r);
	char *mytype = "ipv4";
	char *mysubtype = "";
	char *VIA = "";
	char *asnlist = NULL;
                                        


	/* Identify X-Forwarded-For; include in results after stripping characters. */
	VIA = escape_string (r, (char *) apr_table_get (r->headers_in, "Via"));

	if (!myip)
		myip = "0.0.0.0 undefined";
	if (formdata->testip)
		myip = formdata->testip;
		
        /* If Teredo or 6to4, don't do ASN lookups.  The data will always show *some* ISP, but it isn't ours.*/
	if ((strncmp(myip,"2001:0:",7)==NULL) || (strncmp(myip,"2002:",5)==NULL)) {
	  formdata->getasn=0;
	}	
		

	if (strchr (myip, ':')) {
		mytype = "ipv6";
		mysubtype = mod_ip_find_info(r,myip);
	}
	/* Start generating a reply */

	p = apr_psprintf (r->pool,
			  "%s({\"ip\":\"%s\",\"type\":\"%s\",\"subtype\":\"%s\",\"via\":\"%s\"",
			  formdata->callback ? formdata->callback : "callback", myip, mytype, mysubtype, VIA);
	ap_rputs(p, r);
	output_len = strlen (p) + 4;

	int my_asn ;
	char * asn_name ;

	if (formdata->getasn) {
		my_asn = GetASN(r, myip, &asnlist);
		if (my_asn > 0) {
			p = apr_psprintf (r->pool, ",\"asn\":\"%ld\"", my_asn);
			ap_rputs(p, r);
			output_len += strlen (p) ;
			asn_name = apr_palloc(r->pool, 64) ;
			if ((asn_name != NULL) && (GetASNName(my_asn, asn_name, 64) >= 0)) {
				p = apr_psprintf (r->pool, ",\"asn_name\":\"%s\"", asn_name);
				ap_rputs(p, r);
				output_len += strlen (p) ;
			}
		}
		if ((asnlist) && (asnlist[0])) {
		  p = apr_psprintf(r->pool,  ",\"asnlist\":\"%s\"", asnlist);
		  ap_rputs(p, r);
		  output_len += strlen (p) ;
		}
	}

	ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		       r, "[mod_ip.c] size: `%lld', output_len: `%zd'", (long long) formdata->size, output_len);

	if (formdata->size > output_len) {
		added = formdata->size - output_len - strlen (padding);
		if (added < 0) {
			added = 0;
		}
	} else {
		added = 0;
	}

	ap_log_rerror (APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "[mod_ip.c] added: `%d', padding: `%s'", added, padding);

	if (padding) {
		output_len += strlen (padding) + added;
	}

	if (padding) {
		ap_rputs(padding, r);
		while (added > 0) {
			ap_rwrite(padding_buffer, (added > PADDING_BUFFER_SIZE)?PADDING_BUFFER_SIZE:added, r);
			added -= PADDING_BUFFER_SIZE;
		}
		ap_rputc('\"', r);
	}
	ap_rputs("})\n", r);
}


static int
mod_ip_handler (request_rec * r)
{
	mod_ip_request_t *formdata;

	if ((r->handler == NULL) || (strcmp (r->handler, "mod_ip") != 0)) {
		return DECLINED;
	}
	
	/* Set the headers */
	ap_set_content_type(r,"text/javascript;charset=UTF-8");
	apr_table_set(r->headers_out,"Cache-Control","no-cache");
	apr_table_set(r->headers_out,"Pragma","no-cache");
	apr_table_set(r->headers_out,"Expires","Thu, 01 Jan 1971 00:00:00 GMT");
	apr_table_set(r->headers_out,"X-Mod-Ip",PACKAGE_VERSION);
	
	
	/* pcalloc sets memory to '\0' */
	formdata = (mod_ip_request_t *) apr_pcalloc (r->pool, sizeof (mod_ip_request_t));

	/* GET requests: parse data.  Else, abort. */
	if (r->method_number != M_GET) {
		return HTTP_METHOD_NOT_ALLOWED;
	}
	formdata = parse_form_from_GET (r, formdata);
	if (formdata == NULL) {
		ap_rputs ("<p>Error reading form data!</p>", r);
		/* Bad user. No cookie. */
		return HTTP_BAD_REQUEST;
	}
	/* Display data. */
	if (formdata->callback == NULL) {
		/* interactive user called (no callback specified) */
		ap_set_content_type (r, "text/plain;charset=UTF-8");
	} else {
		/* jsonp called */
		ap_set_content_type (r, "application/javascript;charset=UTF-8");
	}

	/* Report to the user their IP */
	/* ap_rputs (gen_output (r, formdata), r); */
	gen_output(r, formdata);

	/* ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Survived line %u", __LINE__); */

	return OK;
}



/*
 * ################################################################
 * # Apache config file parsing                                   #
 * ################################################################
 */


static const command_rec mod_ip_cmds[] = {
	AP_INIT_TAKE2 ("mod_ip_prefix", mod_ip_config_subnet, NULL, OR_ALL,
		       "Define a known subnet"),
	AP_INIT_TAKE1 ("mod_ip_max_padding", mod_ip_max_padding, NULL, OR_ALL,
		       "Define maximum padding size"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA mod_ip_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* Per-directory configuration handler */
	NULL,				/* Merge handler for per-directory configurations */
	mod_ip_create_svr_conf,		/* Per-server configuration handler */
	mod_ip_merge_svr_conf,		/* Merge handler for per-server configurations */
	mod_ip_cmds,			/* Any directives we may have for httpd */
	mod_ip_hooks			/* Our hook registering function */
};





static const char *
mod_ip_config_subnet_parsed (apr_pool_t * pool, void *CFG, const char *arg1, const char *arg2)
{
//  asm("int3");  /* DEBUGGER */

	char *where = NULL;
	char *bits = NULL;
	apr_status_t rv;
	mod_ip_svr_cfg *cfg = CFG;

	if (!cfg) {
		return "Failed to get config pointer";
	}


	cidrinfo_type *newelt = apr_array_push (cfg->cidrinfo);
	newelt->info = apr_pstrdup (pool, arg2);


	where = apr_pstrdup (pool, arg1);
	if ((bits = ap_strchr (where, '/')) != NULL) {
		*bits++ = '\0';
	}
	rv = apr_ipsubnet_create (&newelt->cidr, where, bits, pool);
	if (rv != APR_SUCCESS) {
		return ("mod_ip_prefix: Bad prefix");
	}
	if (!newelt->cidr) {
	  return "mod_ip_prefix: Bad prefix";
	}


	return (NULL);
};


static const char *
mod_ip_config_subnet (cmd_parms * cmd, void *CFG, const char *arg1, const char *arg2)
{
	/* See Section 9.4.1 Configuration functions */
//  asm("int3");  /* DEBUGGER */

	apr_pool_t *pool = cmd->pool;

	server_rec *s = cmd->server;
	mod_ip_svr_cfg *cfg = ap_get_module_config (s->module_config, &mod_ip_module);

	if (!cfg) {
		return "Failed to get config pointer";
	}
	
	return mod_ip_config_subnet_parsed(pool,cfg,arg1,arg2);
};


void *
mod_ip_create_svr_conf (apr_pool_t * pool, char *x)
{
	mod_ip_svr_cfg *svr = apr_pcalloc (pool, sizeof (mod_ip_svr_cfg));
	svr->cidrinfo = apr_array_make (pool, MAX_PREFIXES, sizeof (cidrinfo_type));
	svr->max_padding = PADDING_DEFAULT_SIZE;
	
	mod_ip_config_subnet_parsed(pool,svr,"2001:0::/32","Teredo");
	mod_ip_config_subnet_parsed(pool,svr,"2002::/16","6to4");
	return svr;
}




static const char *
mod_ip_max_padding(cmd_parms * cmd, void *CFG, const char *arg)
{
	apr_int64_t padding;
	server_rec *s = cmd->server;
	mod_ip_svr_cfg *cfg = ap_get_module_config (s->module_config, &mod_ip_module);
	char buf[120];
	
	padding = apr_atoi64(arg);

	if (padding < 1600)
		return apr_pstrcat(cmd->temp_pool, "mod_ip_max_padding \"", arg,
				   "\" must be a greater than 1600",
				   NULL);

	if (padding > MAX_PADDING_SIZE)
		return apr_pstrcat(cmd->temp_pool, "mod_ip_max_padding \"", arg,
				   "\" too large (>", apr_ltoa(cmd->temp_pool, MAX_PADDING_SIZE), ")",
				   NULL);

	if (padding < 0)
		return apr_pstrcat(cmd->temp_pool, "mod_ip_max_padding \"", arg,
				   "\" must be a non-negative integer",
				   NULL);

	cfg->max_padding = padding;

	return (NULL);
}

static void *
mod_ip_merge_svr_conf (apr_pool_t * pool, void *BASE, void *ADD)
{
	mod_ip_svr_cfg *base = (mod_ip_svr_cfg *) BASE;
	mod_ip_svr_cfg *add = (mod_ip_svr_cfg *) ADD;
	mod_ip_svr_cfg *conf = apr_palloc (pool, sizeof (mod_ip_svr_cfg));
	/* With an APR data type we can delegate all the real work to APR */
	conf->cidrinfo = apr_array_append (pool, base->cidrinfo, add->cidrinfo);
	conf->max_padding = (base->max_padding > add->max_padding)?base->max_padding:add->max_padding;
	return conf;
};





/* Hook our handler into Apache at startup */
static void
mod_ip_hooks (apr_pool_t * pool)
{
	ap_hook_handler (mod_ip_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
