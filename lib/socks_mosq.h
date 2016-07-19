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

#ifndef SOCKS_MOSQ_H
#define SOCKS_MOSQ_H
int _mosquitto_proxy_connect(struct mosquitto *mosq, const char *host, uint16_t port,bool blocking);
int _mosquitto_proxy_write(struct mosquitto *mosq,void *buf, size_t count);
int _mosquitto_proxy_read(struct mosquitto *mosq,void *buf, size_t count);

#endif
