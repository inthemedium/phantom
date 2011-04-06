#include "conn_ctx.h"

struct conn_ctx *
new_conn_ctx(void)
{
	return calloc(sizeof (struct conn_ctx), 1);
}

void
free_conn_ctx(struct conn_ctx *conn)
{
	if (conn->prev_communication_certificate != NULL) {
		X509_free(conn->prev_communication_certificate);
	}
	if (conn->next_communication_certificate != NULL) {
		X509_free(conn->next_communication_certificate);
	}
	if (conn->construction_certificate != NULL) {
		RSA_free(conn->construction_certificate);
	}
	if (conn->routing_certificate != NULL) {
		X509_free(conn->routing_certificate);
	}
	if (conn->next_ip != NULL) {
		free(conn->next_ip);
	}
	if (conn->prev_ip != NULL) {
		free(conn->prev_ip);
	}
	if (conn->keys != NULL) {
		if (conn->keys->ivs != NULL) {
			free(conn->keys->ivs);
		}
		if (conn->keys->keys != NULL) {
			free(conn->keys->keys);
		}
		free(conn->keys);
	}
	if (conn->to_next != NULL) {
		free_ssl_connection(conn->to_next);
	}
	if (conn->rte.data != NULL) {
		free(conn->rte.data);
	}
	free(conn);
}
