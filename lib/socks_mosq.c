/*
Copyright (c) 2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <errno.h>
#include <string.h>

#include "mosquitto_internal.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "send_mosq.h"

#define SOCKS_AUTH_NONE 0x00
#define SOCKS_AUTH_GSS 0x01
#define SOCKS_AUTH_USERPASS 0x02
#define SOCKS_AUTH_NO_ACCEPTABLE 0xFF

#define SOCKS_ATYPE_IP_V4 1 /* four bytes */
#define SOCKS_ATYPE_DOMAINNAME 3 /* one byte length, followed by fqdn no null, 256 max chars */
#define SOCKS_ATYPE_IP_V6 4 /* 16 bytes */

#define SOCKS_REPLY_SUCCEEDED 0x00
#define SOCKS_REPLY_GENERAL_FAILURE 0x01
#define SOCKS_REPLY_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS_REPLY_TTL_EXPIRED 0x06
#define SOCKS_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08

libmosq_EXPORT int mosquitto_proxy_set(struct mosquitto *mosq,int proxy,const char *host, int port, const char *username, const char *password)
{
#ifdef WITH_SOCKS
	if(!mosq) return MOSQ_ERR_INVAL;
	if(!host || strlen(host) > 256) return MOSQ_ERR_INVAL;
	if(port < 1 || port > 65535) return MOSQ_ERR_INVAL;

	if (mosq->proxy_){
		an_close(mosq->proxy_);
		an_destroy(mosq->proxy_);
	}
	
	mosq->proxy_type = proxy;
	if(mosq->proxy_host){
		_mosquitto_free(mosq->proxy_host);
	}

	mosq->proxy_host = _mosquitto_strdup(host);
	if(!mosq->proxy_host){
		return MOSQ_ERR_NOMEM;
	}
	mosq->proxy_port = port;

	if(mosq->proxy_username){
		_mosquitto_free(mosq->proxy_username);
	}
	if(mosq->proxy_password){
		_mosquitto_free(mosq->proxy_password);
	}

	if(username){
		mosq->proxy_username = _mosquitto_strdup(username);
		if(!mosq->proxy_username){
			return MOSQ_ERR_NOMEM;
		}

		if(password){
			mosq->proxy_password = _mosquitto_strdup(password);
			if(!mosq->proxy_password){
				_mosquitto_free(mosq->proxy_username);
				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if (mosq->proxy_type > MOSQ_PROXY_NONE && mosq->proxy_host)
	{
		mosq->proxy_ = an_new_connection();
		
		if ( mosq->proxy_type == MOSQ_PROXY_SOCK5 )
		{		
			char surl[126] = {0};
			char tmp[64];
			sprintf(surl,"socks5://%s:%s",mosq->proxy_host,itoa(mosq->proxy_port,tmp,10));

			if (AN_ERROR_SUCCESS!= an_set_proxy_url(mosq->proxy_, surl))
			return MOSQ_ERR_PROXY;
		}
		else if( mosq->proxy_type == MOSQ_PROXY_HTTP )
		{
			char surl[126] = {0};
			char tmp[64];
			sprintf(surl,"https://%s:%s",mosq->proxy_host,itoa(mosq->proxy_port,tmp,10));

			if (AN_ERROR_SUCCESS!= an_set_proxy_url(mosq->proxy_, surl))
			return MOSQ_ERR_PROXY;
		}
		if (AN_ERROR_SUCCESS != an_set_credentials(mosq->proxy_, mosq->proxy_username, mosq->proxy_password))	
			return MOSQ_ERR_PROXY;
	}
	
	return MOSQ_ERR_SUCCESS;
#else
	return MOSQ_ERR_NOT_SUPPORTED;
#endif
}
int _mosquitto_proxy_connect(struct mosquitto *mosq, const char *host, uint16_t port,bool blocking)
{
	if (!mosq->proxy_host)
		return MOSQ_ERR_PROXY;
	
	if(AN_ERROR_SUCCESS != an_connect_tohostname(mosq->proxy_, host, port ))
		return MOSQ_ERR_PROXY;
	
	if( AN_ERROR_SUCCESS != an_set_blocking(mosq->proxy_, blocking))
		return MOSQ_ERR_PROXY;

	mosq->sock = mosq->proxy_->connection;
	
	return MOSQ_ERR_SUCCESS;
}
#ifdef WITH_SOCKS
int _mosquitto_proxy_write(struct mosquitto *mosq,void *buf, size_t count)
{
	return an_send(mosq->proxy_, buf, count, 0);
}

int _mosquitto_proxy_read(struct mosquitto *mosq,void *buf, size_t count)
{
	return an_recv(mosq->proxy_, buf, count, 0);
}
#endif
