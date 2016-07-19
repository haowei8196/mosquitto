/* ANTINAT
 * =======
 * This software is Copyright (c) 2003-05 Malcolm Smith.
 * No warranty is provided, including but not limited to
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * This code is licenced subject to the GNU General
 * Public Licence (GPL).  See the COPYING file for more.
 */

#include "an_internals.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#include "antinat.h"
#include "an_core.h"

//#include "libntlm-0.3.6/ntlm.h"
#include "ntlm/ntlm.h"
#include "ntlm/auth.h"

static const char *b64t =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
_an_ssl_b64enc (const char *raw, char *enc)
{
	unsigned char inblk[3];
	int i;
	i = 0;
	while (*raw) {
		inblk[i] = (unsigned char) *raw;
		i++;
		if (i == 3) {
			enc[0] = b64t[(inblk[0] & 0xfc) >> 2];
			enc[1] =
				b64t[((inblk[0] & 0x03) << 4) + ((inblk[1] & 0xf0) >> 4)];
			enc[2] =
				b64t[((inblk[1] & 0x0f) << 2) + ((inblk[2] & 0xc0) >> 6)];
			enc[3] = b64t[(inblk[2] & 0x3f)];
			i = 0;
			enc += 4;
		}
		raw++;
	}
	switch (i) {
	case 2:
		enc[0] = b64t[(inblk[0] & 0xfc) >> 2];
		enc[1] = b64t[((inblk[0] & 0x03) << 4) + ((inblk[1] & 0xf0) >> 4)];
		enc[2] = b64t[((inblk[1] & 0x0f) << 2)];
		enc[3] = '=';
		enc += 4;
		break;
	case 1:
		enc[0] = b64t[(inblk[0] & 0xfc) >> 2];
		enc[1] = b64t[((inblk[0] & 0x03) << 4)];
		enc[2] = '=';
		enc[3] = '=';
		enc += 4;
		break;
	}
	enc[0] = '\0';
	return AN_ERROR_SUCCESS;
}
#define OK	(0)
#define FAIL	(-1)
#define BUFOVER	(-2)

#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])

static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????";

static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};


int encode64(const char *_in, unsigned inlen,
		  char *_out, unsigned outmax, unsigned *outlen)
{
    const unsigned char *in = (const unsigned char *)_in;
    unsigned char *out = (unsigned char *)_out;
    unsigned char oval;
    char *blah;
    unsigned olen;

    /* Will it fit? */
    olen = (inlen + 2) / 3 * 4;
    if (outlen)
      *outlen = olen;
    if (outmax < olen)
      return BUFOVER;

    /* Do the work... */
    blah=(char *) out;
    while (inlen >= 3) {
      /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        *out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = basis_64[in[2] & 0x3f];
        in += 3;
        inlen -= 3;
    }
    if (inlen > 0) {
      /* user provided max buffer size; make sure we don't go over it */
        *out++ = basis_64[in[0] >> 2];
        oval = (in[0] << 4) & 0x30;
        if (inlen > 1) oval |= in[1] >> 4;
        *out++ = basis_64[oval];
        *out++ = (inlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }

    if (olen < outmax)
      *out = '\0';
    
    return OK;
}


int decode64(const char *in, unsigned inlen,
		  char *out, unsigned *outlen)
{
    unsigned len = 0,lup;
    int c1, c2, c3, c4;

    /* check parameters */
    if (out==NULL) return FAIL;

    /* xxx these necessary? */
    if (in[0] == '+' && in[1] == ' ') in += 2;
    if (*in == '\r') return FAIL;

    for (lup=0;lup<inlen/4;lup++)
    {
        c1 = in[0];
        if (CHAR64(c1) == -1) return FAIL;
        c2 = in[1];
        if (CHAR64(c2) == -1) return FAIL;
        c3 = in[2];
        if (c3 != '=' && CHAR64(c3) == -1) return FAIL; 
        c4 = in[3];
        if (c4 != '=' && CHAR64(c4) == -1) return FAIL;
        in += 4;
        *out++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
        ++len;
        if (c3 != '=') {
            *out++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
            ++len;
            if (c4 != '=') {
                *out++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
                ++len;
            }
        }
    }

    *out=0; /* terminate string */
    *outlen=len;
    return OK;
}

int
an_ssl_close (ANCONN conn)
{
	return _an_generic_close (conn);
}

int
an_ssl_connect_tosockaddr (ANCONN conn, SOCKADDR * sa, int len)
{
	char buf[20];
	SOCKADDR_IN *sin;
	int ret;
	if (sa == NULL)
		return AN_ERROR_INVALIDARG;
	if (sa->sa_family != AF_INET)
		return AN_ERROR_NOTSUPPORTED;

	sin = (SOCKADDR_IN *) sa;

#ifdef WIN32
	sprintf (buf, "%u.%u.%u.%u",
			 (unsigned int) (sin->sin_addr.S_un.S_un_b.s_b1) ,
			 (unsigned int) (sin->sin_addr.S_un.S_un_b.s_b2),
			 (unsigned int) (sin->sin_addr.S_un.S_un_b.s_b3),
			 (unsigned int) sin->sin_addr.S_un.S_un_b.s_b4);
#else
	unsigned char caddr[4];
	memcpy(caddr, sin->sin_addr.s_addr, 4);
	sprintf (buf, "%u.%u.%u.%u",
		(unsigned int) (caddr[0]) ,
		(unsigned int) (caddr[1]),
		(unsigned int) (caddr[2]),
		(unsigned int) (caddr[3]));
#endif


	ret = an_ssl_connect_tohostname (conn, buf, ntohs (sin->sin_port));
	if (ret == AN_ERROR_SUCCESS) {
		_an_setsockaddr (&conn->peer, sa, len);
	}
	return ret;
}
int do_ntlm_auth(ANCONN conn, const char *hostname, 
				  unsigned short port, const unsigned short oldblocking)
{
	int ret, outlen;
	char buf[2048] = {0};
	char authbuf[512] = {0};
	char tmp[512] = {0};
	char challenge[512] = {0};
	char *cptr;
	char* request = 0;
	char* response = 0;

	struct auth_s* au = new_auth();

	if(conn->proxy_domain)
		strcpy(au->domain, conn->proxy_domain);
	else
		strcpy(au->domain, "TEMPDOMAIN");
	if(conn->proxy_user)
		strcpy(au->user, conn->proxy_user);
	//strcpy(au->workstation, "TEMPWORKSTATION");
	if(conn->proxy_pass)
		au->passntlm2 = ntlm2_hash_password(au->user, au->domain, conn->proxy_pass);

	ret = ntlm_request(&request, au);
	if(0 == ret)
	{
		free_auth(au);
		return -1;
	}
	encode64(request, ret, authbuf, sizeof(authbuf), &outlen);
	if(request)
		free(request);

	if(443 == port)
		sprintf (buf,
		"CONNECT %s:%i HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Mozilla/4.0\r\nHost: %s\r\nPragma: no-cache\r\nAccept: */*\r\nContent-Type: text/html\r\nContent-Length: 0\r\nProxy-Authorization: NTLM %s\r\n\r\n",
			hostname, port, hostname, authbuf);
	else
		sprintf (buf,
		"GET http://%s:%i HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Mozilla/4.0\r\nHost: %s\r\nPragma: no-cache\r\nAccept: */*\r\nContent-Type: text/html\r\nContent-Length: 0\r\nProxy-Authorization: NTLM %s\r\n\r\n",
			hostname, port, hostname, authbuf);

	ret = _an_generic_send_all (conn, buf, strlen (buf));
	if (ret != AN_ERROR_SUCCESS) {
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		free_auth(au);
		return ret;
	}

	do 
	{
		ret = _an_generic_getline (conn, buf, sizeof (buf));
		if (ret != AN_ERROR_SUCCESS) {
			an_ssl_close (conn);
			an_set_blocking (conn, oldblocking);
			free_auth(au);
			return ret;
		}	
		cptr = strstr(buf, "NTLM ");
		if (NULL != cptr) {
			cptr += 5;
			strcpy(tmp, cptr);
			break;
		}
	} 
	while(0 == ret);

	while (strlen (buf) > 0) {
		ret = _an_generic_getline (conn, buf, sizeof (buf));
		if (ret != AN_ERROR_SUCCESS) {
			an_ssl_close (conn);
			an_set_blocking (conn, oldblocking);
			free_auth(au);
			return ret;
		}
	}

	decode64(tmp, strlen(tmp), challenge, &outlen);
    
	ret = ntlm_response(&response, challenge, outlen, au);
	if(0 == ret)
	{
		free_auth(au);
		return -1;
	}
	encode64(response, ret, authbuf, sizeof(authbuf), &outlen);
	if(response)
		free(response);

	if(443 == port)
		sprintf (buf,
		"CONNECT %s:%i HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Mozilla/4.0\r\nHost: %s\r\nPragma: no-cache\r\nAccept: */*\r\nContent-Type: text/html\r\nContent-Length: 0\r\nProxy-Authorization: NTLM %s\r\n\r\n",
			hostname, port, hostname, authbuf);
	else
		sprintf (buf,
		"GET http://%s:%i HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Mozilla/4.0\r\nHost: %s\r\nPragma: no-cache\r\nAccept: */*\r\nContent-Type: text/html\r\nContent-Length: 0\r\nProxy-Authorization: NTLM %s\r\n\r\n",
			hostname, port, hostname, authbuf);

	ret = _an_generic_send_all (conn, buf, strlen (buf));
	if (ret != AN_ERROR_SUCCESS) {
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		free_auth(au);
		return ret;
	}
	ret = _an_generic_getline (conn, buf, sizeof (buf));
	if (ret != AN_ERROR_SUCCESS) {
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		free_auth(au);
		return ret;
	}
	cptr = strchr (buf, ' ');
	if (cptr) {
		cptr++;
		ret = atoi (cptr);
		if (ret != 200) {
			/* Connect failed :( */
			an_ssl_close (conn);
			an_set_blocking (conn, oldblocking);
			free_auth(au);
			return AN_ERROR_PROXY;
		}
	} else {
		/* No space in response, bad response */
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		free_auth(au);
		return AN_ERROR_PROXY;
	}
	//while (strlen (buf) > 0) {
	//	ret = _an_generic_getline (conn, buf, sizeof (buf));
	//	if (ret != AN_ERROR_SUCCESS) {
	//		an_ssl_close (conn);
	//		an_set_blocking (conn, oldblocking);
	//		free_auth(au);
	//		return ret;
	//	}
	//}
	
	an_set_blocking (conn, oldblocking);
	conn->mode = AN_MODE_CONNECTED;
	free_auth(au);
	return AN_ERROR_SUCCESS;
}

int
an_ssl_connect_tohostname (ANCONN conn, const char *hostname,
						   unsigned short port)
{
	unsigned short oldblocking;
	int ret;
	char buf[1024];
	char *cptr;

	int content_length = 0;
	char *pdest = NULL;

	char authbuf[512];
	memset((void*)authbuf, 0, 512);

	if (conn == NULL)
		return AN_ERROR_INVALIDARG;
	if (hostname == NULL)
		return AN_ERROR_INVALIDARG;
	if (conn->proxy_type != AN_SERV_SSL)
		return AN_ERROR_INVALIDARG;
	if (conn->proxy_user == NULL && !(conn->authmask & (1 << AN_AUTH_ANON)))
		return AN_ERROR_NOTSUPPORTED;
	if (conn->proxy_user != NULL && !(conn->authmask & (1 << AN_AUTH_ANON)) &&
		!(conn->authmask & (1 << AN_AUTH_BASIC)))
		return AN_ERROR_NOTSUPPORTED;

	oldblocking = conn->blocking;
	an_set_blocking (conn, 1);

	ret = _an_rawconnect (conn);
	if (ret != AN_ERROR_SUCCESS) {
		an_set_blocking (conn, oldblocking);
		return ret;
	}

	if (conn->hostname != NULL)
		free (conn->hostname);
	conn->hostname = (char *) malloc (strlen (hostname) + 1);
	if (conn->hostname == NULL)
		return AN_ERROR_NOMEM;
	strcpy (conn->hostname, hostname);

	if (conn->proxy_user != NULL && (conn->authmask & (1 << AN_AUTH_BASIC))) {
		char rawauthbuf[512];
		/* Sanity check. */
		if (strlen (conn->proxy_user) < 150) {
			strcpy (rawauthbuf, conn->proxy_user);
			strcat (rawauthbuf, ":");
			if (conn->proxy_pass && (strlen (conn->proxy_pass) < 150)) {
				strcat (rawauthbuf, conn->proxy_pass);
			}
		} else {
			strcpy (rawauthbuf, ":");
		}

		_an_ssl_b64enc (rawauthbuf, authbuf);

		if(443 == port)
			sprintf (buf,
			"CONNECT %s:%i HTTP/1.1\r\nProxy-Authorization: Basic %s\r\nHost: %s\r\nPragma: no-cache\r\nProxy-Connection: Keep-Alive\r\n\r\n",
			hostname, port, authbuf, hostname);
		else
			sprintf (buf,
			"GET http://%s:%i/ HTTP/1.1\r\nProxy-Authorization: Basic %s\r\nHost: %s\r\nPragma: no-cache\r\nProxy-Connection: Keep-Alive\r\n\r\n",
			hostname, port, authbuf, hostname);

	} else {
		if(443 == port)
			sprintf (buf, "CONNECT %s:%i HTTP/1.1\r\nHost: %s\r\nPragma: no-cache\r\nProxy-Connection: Keep-Alive\r\n\r\n", hostname, port, hostname);
		else
			sprintf (buf, "GET http://%s:%i/ HTTP/1.1\r\nHost: %s\r\nPragma: no-cache\r\nProxy-Connection: Keep-Alive\r\n\r\n", hostname, port, hostname);

	}

	ret = _an_generic_send_all (conn, buf, strlen (buf));
	if (ret != AN_ERROR_SUCCESS) {
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		return ret;
	}

	ret = _an_generic_getline (conn, buf, sizeof (buf));
	if (ret != AN_ERROR_SUCCESS) {
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		return ret;
	}
	cptr = strchr (buf, ' ');
	if (cptr) {
		cptr++;
		ret = atoi (cptr);
		if (ret != 200/* && conn->proxy_user != NULL*/) {
			if(conn->proxy_user)
			{
				//do 
				//{
				//	ret = _an_generic_getline (conn, buf, sizeof (buf));
				//} 
				//while(0 == ret);
#ifdef WIN32
				Sleep (1);
#else
				usleep(1);
#endif				
				an_ssl_close (conn);
				ret = _an_rawconnect (conn);
				if (ret != AN_ERROR_SUCCESS) {
					an_set_blocking (conn, oldblocking);
					return ret;
				}

				ret = do_ntlm_auth(conn, hostname, port, oldblocking);
				if (ret != AN_ERROR_SUCCESS) {
					an_ssl_close (conn);
					an_set_blocking (conn, oldblocking);
					return ret;
				}
			}
			else
			{
				/* Connect failed :( */
				an_ssl_close (conn);
				an_set_blocking (conn, oldblocking);
				return ret;
			}
		}
	} else {
		/* No space in response, bad response */
		an_ssl_close (conn);
		an_set_blocking (conn, oldblocking);
		return AN_ERROR_PROXY;
	}

	while (strlen (buf) > 0) {
		ret = _an_generic_getline (conn, buf, sizeof (buf));
		if (ret != AN_ERROR_SUCCESS) {
			an_ssl_close (conn);
			an_set_blocking (conn, oldblocking);
			return ret;
		}
		pdest = strstr(buf, "Content-Length:");
		if (pdest != NULL) {
			content_length = atoi (pdest + 16);
		}
	}

	if(0 != content_length)
	{
		char* tmp = malloc (sizeof (char) * content_length);
		int recv_len = 0;
		int tmp_len = 0;
		while(recv_len < content_length){
			tmp_len = _an_generic_recv (conn, tmp, content_length, 0);
			if (tmp_len < 1)
				break;
			recv_len += tmp_len;
		}
		free(tmp);
	}

	if(conn->authbuf)
	{
		free(conn->authbuf);
		conn->authbuf = NULL;
	}
	if(authbuf)
	{
		conn->authbuf = (char *) malloc (strlen (authbuf) + 1);
		strcpy(conn->authbuf, authbuf);
	}

	an_set_blocking (conn, oldblocking);
	conn->mode = AN_MODE_CONNECTED;
	return AN_ERROR_SUCCESS;
}

int
an_ssl_recv (ANCONN conn, void *buf, int len, int flags)
{
	if (conn->connection == AN_INVALID_CONNECTION)
		return -1;
	return _an_generic_recv (conn, buf, len, flags);
}

int
an_ssl_send (ANCONN conn, void *buf, int len, int flags)
{
	char *tcptr = NULL;
	char *connection_cptr = NULL;
	int sub_len1 = 0;
	int sub_len2 = 0;
	int total_len = 0;
	if (conn->connection == AN_INVALID_CONNECTION)
		return -1;

	if (NULL != strstr(buf, "POST") || NULL != strstr(buf, "GET")) {
		char *http_tag = "http://";
		char insert_buf[1024];
		char *keepalive_tag = 0;
		char *cptr = 0;

		if(conn->authbuf)
			sprintf(insert_buf, "Proxy-Connection: Keep-Alive\r\nPragma: no-cache\r\nProxy-Authorization: Basic %s\r\n", conn->authbuf);
		else
			sprintf(insert_buf, "Proxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n");

		keepalive_tag = insert_buf;
		cptr = strstr(buf, http_tag);
		if (NULL != cptr)
			sub_len1 = cptr-(char*)buf;
		if (NULL != cptr || sub_len1 > 5){
			int ret=0;
			int plus_len = strlen (conn->hostname) + strlen(http_tag) + strlen(keepalive_tag);
			char *replaced_buf = (char *) malloc (plus_len + len);
			if (replaced_buf == NULL)
			{
				return AN_ERROR_NOMEM;
			}
			tcptr = strchr(buf, '/');
			connection_cptr = strstr(buf, "Connection: keep-alive");
			if (tcptr) {
				sub_len1 = tcptr-(char*)buf;
				if(connection_cptr != NULL)
					sub_len2 = connection_cptr -(char*)buf;
				memcpy(replaced_buf, buf, sub_len1);
				memcpy(replaced_buf + sub_len1, http_tag, strlen(http_tag));
				memcpy(replaced_buf + sub_len1 + strlen(http_tag), conn->hostname, strlen(conn->hostname));
				if(connection_cptr == NULL){
					memcpy(replaced_buf + sub_len1 + strlen(http_tag) + strlen(conn->hostname), tcptr, len-sub_len1);
				}
				else{
					memcpy(replaced_buf + sub_len1 + strlen(http_tag) + strlen(conn->hostname), tcptr, sub_len2-sub_len1);
					memcpy(replaced_buf + strlen(http_tag) + strlen(conn->hostname) + sub_len2, keepalive_tag, strlen(keepalive_tag));
					memcpy(replaced_buf + strlen(http_tag) + strlen(conn->hostname) + sub_len2 + strlen(keepalive_tag), connection_cptr, len-sub_len2);
				}
			}
			total_len = len + plus_len - ((connection_cptr == NULL)?strlen(keepalive_tag):0);
			ret = _an_generic_send (conn, replaced_buf, total_len, flags);
			free(replaced_buf);
			return ret;
		}
	}
	return _an_generic_send (conn, buf, len, flags);
}
