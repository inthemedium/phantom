#include "kademlia_rpc.h"

static struct rpc_return *
new_rpc_return(void)
{
	struct rpc_return *r;
	r = calloc(1, sizeof(struct rpc_return));
	if (r == NULL) {
		return NULL;
	}
	r->success = -1;
	return r;
}

void
free_rpc_return(struct rpc_return *r)
{
	int i;
	for (i = 0; i < KADEMLIA_K; i++) {
		if (r->nodes[i] != NULL) {
			free_kad_node_info(r->nodes[i]);
		}
	}
	if (r->data != NULL) {
		free(r->data);
	}
	free(r);
}

static int
check_node_info_message(const NodeInfo *n)
{
	if (n->id.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	if (n->port>>16) {
		return -1;
	}
	return 0;
}

static int
validate_find_value_reply(const FindValueReply *r)
{
	uint32_t i;
	int ret;
	if (r->success) {
		if (! r->has_data) {
			return -1;
		}
		return 0;
	}
	if (r->n_nodes == 0) {
		return -1;
	}
	if (r->n_nodes > KADEMLIA_K) {
		return -1;
	}
	for (i = 0; i < r->n_nodes; i++) {
		ret = check_node_info_message(r->nodes[i]);
		if (ret != 0) {
			return -1;
		}
	}
	return 0;
}

static struct kad_node_info *
new_node_info_from_message(const NodeInfo *msg)
{
	struct kad_node_info *r;
	X509 *cert, *pbc;
	struct X509_flat f;
	f.data = msg->cert.data;
	f.len = msg->cert.len;
	cert = read_x509_from_x509_flat(&f);
	if (cert == NULL) {
		return NULL;
	}
	f.data = msg->pbc.data;
	f.len = msg->pbc.len;
	pbc = read_x509_from_x509_flat(&f);
	if (pbc == NULL) {
		X509_free(cert);
		return NULL;
	}
	r = new_kad_node_info(msg->id.data, msg->ip, msg->port, cert, pbc);
	X509_free(cert);
	X509_free(pbc);
	if (r == NULL) {
		return NULL;
	}
	return r;
}

static struct ssl_connection *
ssl_connect_check_hash(const char *ip, uint16_t port, X509 *cert, EVP_PKEY *privkey, uint32_t timeout, const uint8_t *peer_id)
{
	int ret;
	struct ssl_connection *c;
	uint8_t hash[SHA_DIGEST_LENGTH];
	assert(peer_id);
	assert(ip);
	assert(cert);
	assert(privkey);
	c = create_ssl_connection_tmout(ip, port, cert, privkey, timeout);
	if (c == NULL) {
		return NULL;
	}
	ret = X509_hash(c->peer_cert, hash);
	if (ret != 0) {
		free_ssl_connection(c);
		return NULL;
	}
	if (memcmp(hash, peer_id, SHA_DIGEST_LENGTH)) {
		printf("fake node encountered with ip %s\n", ip);
		free_ssl_connection(c);
		return NULL;
	}
	return c;
}

static int
extract_kad_nodes(NodeInfo **nodes, uint32_t nnodes, struct kad_node_info **outnodes)
{
	uint32_t i, j, ret;
	if (nnodes > KADEMLIA_K) {
		return -1;
	}
	for (i = 0; i < nnodes; i++) {
		ret = check_node_info_message(nodes[i]);
		if (ret != 0) {
			return -1;
		}
	}
	for (i = 0; i < nnodes; i++) {
		outnodes[i] = new_node_info_from_message(nodes[i]);
		if (outnodes[i] == NULL) {
			j = 0;
			while (j < i) {
				free_kad_node_info(outnodes[j]);
				j++;
			}
			return -1;
		}
	}
	return 0;
}

struct rpc_return *
rpc_find_node(uint8_t *id, const struct kad_node_info *n, X509 *cert, EVP_PKEY *privkey, NodeInfo *self)
{
	FindCloseNodes package;
	FindCloseNodesReply *reply;
	struct rpc_return *rpc_ret;
	struct ssl_connection *c;
	uint8_t *packed, *received;
	uint32_t size, ret, have;
	assert(id);
	assert(n);
	assert(n->ip);
	assert(self);
	rpc_ret = new_rpc_return();
	if (rpc_ret == NULL) {
		return NULL;
	}
	rpc_ret->success = 0;
	find_close_nodes__init(&package);
	package.id.data = id;
	package.id.len = SHA_DIGEST_LENGTH;
	package.self = self;
	size = find_close_nodes__get_packed_size(&package);
	packed = malloc(size + 4);
	if (packed == NULL) {
		free_rpc_return(rpc_ret);
		return NULL;
	}
	c = ssl_connect_check_hash(n->ip, n->port, cert, privkey, FIND_TIMEOUT, n->id);
	if (c == NULL) {
		free(packed);
		free_rpc_return(rpc_ret);
		return NULL;
	}
	ret = find_close_nodes__pack(&package, packed + 4);
	assert(ret == size);
	serialize_32_t(KAD_MAGIC_FIND_NODE, packed);
	ret = write_package(c->ssl, packed, size + 4);
	free(packed);
	if (ret != 0) {
		free_ssl_connection(c);
		free_rpc_return(rpc_ret);
		return NULL;
	}
	received = read_package(c->ssl, &have);
	free_ssl_connection(c);
	if (received == NULL) {
		free_rpc_return(rpc_ret);
		return NULL;
	}
	reply = find_close_nodes_reply__unpack(NULL, have, received);
	free(received);
	if (reply == NULL) {
		free_rpc_return(rpc_ret);
		return NULL;
	}
	update_table_relay(n);
	ret = extract_kad_nodes(reply->nodes, reply->n_nodes, rpc_ret->nodes);
	if (ret != 0) {
		rpc_ret->nnodes = 0;
		rpc_ret->success = 0;
	} else {
		rpc_ret->nnodes = reply->n_nodes;
		rpc_ret->success = 1;
	}
	find_close_nodes_reply__free_unpacked(reply, NULL);
	return rpc_ret;
}

struct rpc_return *
rpc_find_value(uint8_t *key, const struct kad_node_info *n, X509 *cert, EVP_PKEY *privkey, NodeInfo *self)
{
	FindValue package;
	FindValueReply *reply;
	struct rpc_return *rpc_ret;
	uint8_t *packed, *received;
	struct ssl_connection *c;
	uint32_t size, ret, have;
	assert(key);
	assert(n);
	assert(self);
	rpc_ret = new_rpc_return();
	if (rpc_ret == NULL) {
		return NULL;
	}
	find_value__init(&package);
	package.key.len = SHA_DIGEST_LENGTH;
	package.key.data = key;
	package.self = self;
	size = find_value__get_packed_size(&package);
	packed = malloc(size + 4);
	if (packed == NULL) {
		free_rpc_return(rpc_ret);
		return NULL;
	}
	ret = find_value__pack(&package, packed + 4);
	assert (ret == size);
	serialize_32_t(KAD_MAGIC_FIND_VALUE, packed);
	c = ssl_connect_check_hash(n->ip, n->port, cert, privkey, FIND_TIMEOUT, n->id);
	if (c == NULL) {
		free(packed);
		free_rpc_return(rpc_ret);
		return NULL;
	}
	ret = write_package(c->ssl, packed, size + 4);
	free(packed);
	if (ret != 0) {
		free_ssl_connection(c);
		free_rpc_return(rpc_ret);
		return NULL;
	}
	received = read_package(c->ssl, &have);
	free_ssl_connection(c);
	if (received == NULL) {
		free_rpc_return(rpc_ret);
		return NULL;
	}
	reply = find_value_reply__unpack(NULL, have, received);
	free(received);
	if (reply == NULL) {
		free_rpc_return(rpc_ret);
		return NULL;
	}
	ret = validate_find_value_reply(reply);
	if (ret != 0) {
		find_value_reply__free_unpacked(reply, NULL);
		free_rpc_return(rpc_ret);
		return NULL;
	}
	if (reply->success) {
		rpc_ret->data = malloc(reply->data.len);
		if (rpc_ret->data == NULL) {
			find_value_reply__free_unpacked(reply, NULL);
			free_rpc_return(rpc_ret);
			return NULL;
		}
		memcpy(rpc_ret->data, reply->data.data, reply->data.len);
		rpc_ret->len = reply->data.len;
		rpc_ret->success = 1;
		find_value_reply__free_unpacked(reply, NULL);
		update_table_relay(n);
		return rpc_ret;
	}
	rpc_ret->success = 0;
	rpc_ret->nnodes = extract_kad_nodes(reply->nodes, reply->n_nodes, rpc_ret->nodes);
	find_value_reply__free_unpacked(reply, NULL);
	update_table_relay(n);
	return rpc_ret;
}

int
rpc_store(uint8_t *key, uint8_t *data, uint32_t len, const struct kad_node_info *store_to, X509 *cert, EVP_PKEY *privkey, NodeInfo *self)
{
	Store package;
	StoreReply *reply;
	uint8_t *packed, *received;
	uint32_t size, ret, have;
	struct ssl_connection *c;
	assert(key);
	assert(data);
	assert(len);
	assert(store_to);
	assert(self);
	store__init(&package);
	package.key.data = key;
	package.key.len = SHA_DIGEST_LENGTH;
	package.data.data = data;
	package.data.len = len;
	package.self = self;
	size = store__get_packed_size(&package);
	packed = malloc(size + 4);
	if (packed == NULL) {
		return -1;
	}
	ret = store__pack(&package, packed + 4);
	assert(ret == size);
	serialize_32_t(KAD_MAGIC_STORE, packed);
	c = ssl_connect_check_hash(store_to->ip, store_to->port, cert, privkey, STORE_TIMEOUT, store_to->id);
	if (c == NULL) {
		free(packed);
		return -1;
	}
	ret = write_package(c->ssl, packed, size + 4);
	free(packed);
	if (ret != 0) {
		free_ssl_connection(c);
		return -1;
	}
	received = read_package(c->ssl, &have);
	free_ssl_connection(c);
	if (received == NULL) {
		return -1;
	}
	reply = store_reply__unpack(NULL, have, received);
	free(received);
	if (reply == NULL) {
		return -1;
	}
	update_table_relay(store_to);
	if (reply->success) {
		store_reply__free_unpacked(reply, NULL);
		return 0;
	}
	store_reply__free_unpacked(reply, NULL);
	return -1;
}

static int
validate_find_close_nodes(const FindCloseNodes *package)
{
	assert(package);
	if (package->id.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	return check_node_info_message(package->self);
}

static int
validate_find_value(const FindValue *package)
{
	assert(package);
	if (package->key.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	return check_node_info_message(package->self);
}

static int
validate_store_request(const Store *request)
{
	assert(request);
	if (request->key.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	if (request->data.len < 1) {
		return -1;
	}
	return check_node_info_message(request->self);
}

static void
free_node_info_array(NodeInfo **a, int len)
{
	int i;
	if (a == NULL) {
		return;
	}
	for (i = 0; i < len; i++) {
		if (a[i] != NULL) {
			if (a[i]->cert.data != NULL) {
				free(a[i]->cert.data);
			}
			if (a[i]->pbc.data != NULL) {
				free(a[i]->pbc.data);
			}
			free(a[i]);
		}
	}
	free(a);
}

static NodeInfo **
new_node_info_array(const struct kad_node_list *list)
{
	NodeInfo **out;
	int i;
	struct kad_node_info *help1, *help2;
	struct X509_flat *fc;
	if (list == NULL || list->nentries == 0) {
		return NULL;
	}
	out = calloc(list->nentries, sizeof (NodeInfo *));
	if (out == NULL) {
		return NULL;
	}
	for (i = 0; i < list->nentries; i++) {
		out[i] = calloc(1, sizeof (NodeInfo));
		if (out [i] == NULL) {
			free_node_info_array(out, i);
			return NULL;
		}
		node_info__init(out[i]);
	}
	i = 0;
	LIST_for_all(&list->list, help1, help2) {
		out[i]->id.len = SHA_DIGEST_LENGTH;
		out[i]->id.data = help1->id;
		out[i]->port = help1->port;
		out[i]->ip = help1->ip;
		fc = flatten_X509(help1->cert);
		if (fc == NULL) {
			free_node_info_array(out, list->nentries);
			return NULL;
		}
		out[i]->cert.data = malloc(fc->len);
		if (out[i]->cert.data == NULL) {
			free_node_info_array(out, list->nentries);
			free_X509_flat(fc);
			return NULL;
		}
		out[i]->cert.len = fc->len;
		memcpy(out[i]->cert.data, fc->data, fc->len);
		free_X509_flat(fc);
		fc = flatten_X509(help1->pbc);
		if (fc == NULL) {
			free_node_info_array(out, list->nentries);
			return NULL;
		}
		out[i]->pbc.data = malloc(fc->len);
		if (out[i]->pbc.data == NULL) {
			free_node_info_array(out, list->nentries);
			free_X509_flat(fc);
			return NULL;
		}
		out[i]->pbc.len = fc->len;
		memcpy(out[i]->pbc.data, fc->data, fc->len);
		free_X509_flat(fc);
		i++;
	}
	assert(i == list->nentries);
	return out;
}

int handle_rpc_find_node(SSL *from, X509 *cert, uint8_t *package, int size)
{
	FindCloseNodes *request;
	FindCloseNodesReply reply;
	struct kad_node_list *list;
	uint32_t packed_size, ret;
	struct kad_node_info *n;
	uint8_t *packed, hash[SHA_DIGEST_LENGTH];
	assert(from);
	assert(cert);
	assert(package);
	if (size < 1) {
		return -1;
	}
	request = find_close_nodes__unpack(NULL, size, package);
	if (request == NULL) {
		return -1;
	}
	ret = validate_find_close_nodes(request);
	if (ret != 0) {
		find_close_nodes__free_unpacked(request, NULL);
		return 0;
	}
	ret = X509_hash(cert, hash);
	if (ret != 0) {
		find_close_nodes__free_unpacked(request, NULL);
		return 0;
	}
	list = get_k_closest_nodes(request->id.data, hash);
	find_close_nodes_reply__init(&reply);
	if (list == NULL) {
		/* return empty reply */
		reply.n_nodes = 0;
	} else {
		assert(list->nentries <= KADEMLIA_K);
		reply.n_nodes = list->nentries;
		reply.nodes = new_node_info_array(list);
		if (reply.nodes == NULL) {
			find_close_nodes__free_unpacked(request, NULL);
			free_kad_node_list(list);
			return 0;
		}
	}
	packed_size = find_close_nodes_reply__get_packed_size(&reply);
	packed = malloc(packed_size);
	if (packed == NULL) {
		find_close_nodes__free_unpacked(request, NULL);
		if (list != NULL) {
			free_node_info_array(reply.nodes, list->nentries);
		}
		free_kad_node_list(list);
		return 0;
	}
	ret = find_close_nodes_reply__pack(&reply, packed);
	assert(ret == packed_size);
	if (list != NULL) {
		free_node_info_array(reply.nodes, list->nentries);
		free_kad_node_list(list);
	}
	ret = write_package(from, packed, packed_size);
	free(packed);
	if (ret != 0) {
		find_close_nodes__free_unpacked(request, NULL);
		return 0;
	}
	/* update node info */
	ret = extract_kad_nodes(&request->self, 1, &n);
	find_close_nodes__free_unpacked(request, NULL);
	if (ret != 0) {
		free_kad_node_info(n);
		return 0;
	}
	update_table_relay(n);
	free_kad_node_info(n);
	return 0;
}

int handle_rpc_find_value(SSL *from, X509 *cert, uint8_t *package, int size)
{
	FindValue *request;
	FindValueReply reply;
	uint32_t ret, packed_size, iret;
	uint8_t *packed;
	struct kad_node_info *n;
	struct kad_node_list *list;
	assert(from);
	assert(cert);
	assert(package);
	if (size < 1) {
		return -1;
	}
	request = find_value__unpack(NULL, size, package);
	if (request == NULL) {
		return -1;
	}
	ret = validate_find_value(request);
	if (ret != 0) {
		find_value__free_unpacked(request, NULL);
		return 0;
	}
	find_value_reply__init(&reply);
	list = NULL;
	reply.data.data = NULL;
	iret = local_find(request->key.data, &reply.data.data, &reply.data.len);
	if (iret == 0) { /* value found */
		assert(reply.data.data != NULL);
		reply.success = 1;
		reply.has_data = 1;
		reply.n_nodes = 0;
	} else {
		/* nothing was found - return nodes */
		uint8_t hash[SHA_DIGEST_LENGTH];
		reply.success = 0;
		reply.has_data = 0;
		ret = X509_hash(cert, hash);
		if (ret != 0) {
			find_value__free_unpacked(request, NULL);
			return 0;
		}
		list = get_k_closest_nodes(request->key.data, hash);
		if (list != NULL) {
			reply.n_nodes = list->nentries;
			reply.nodes = new_node_info_array(list);
			if (reply.nodes == NULL) {
				find_value__free_unpacked(request, NULL);
				free_kad_node_list(list);
				return 0;
			}
		} else {
			reply.n_nodes = 0;
		}
	}
	packed_size = find_value_reply__get_packed_size(&reply);
	packed = malloc(packed_size);
	if (packed == NULL) {
		if (reply.data.data != NULL) {
			free(reply.data.data);
		}
		find_value__free_unpacked(request, NULL);
		free_kad_node_list(list);
		return 0;
	}
	ret = find_value_reply__pack(&reply, packed);
	assert(ret == packed_size);
	if (list != NULL) {
		free_node_info_array(reply.nodes, list->nentries);
		free_kad_node_list(list);
	}
	ret = write_package(from, packed, packed_size);
	if (reply.data.data != NULL) {
		free(reply.data.data);
	}
	free(packed);
	if (ret != 0) {
		find_value__free_unpacked(request, NULL);
		return 0;
	}
	/* update node info */
	ret = extract_kad_nodes(&request->self, 1, &n);
	find_value__free_unpacked(request, NULL);
	if (ret != 0) {
		return 0;
	}
	update_table_relay(n);
	free_kad_node_info(n);
	return 0;
}

int handle_rpc_store(SSL *from, X509 *cert, uint8_t *package, int size)
{
	Store *request;
	StoreReply reply;
	uint32_t packed_size, ret;
	struct kad_node_info *n;
	uint8_t *packed;
	assert(from);
	assert(cert);
	assert(package);
	if (size < 1) {
		return -1;
	}
	request = store__unpack(NULL, size, package);
	if (request == NULL) {
		return -1;
	}
	ret = validate_store_request(request);
	if (ret != 0) {
		store__free_unpacked(request, NULL);
		return 0;
	}
	store_reply__init(&reply);
	ret = local_store(request->key.data, request->data.data, request->data.len);
	if (ret == 0) {
		reply.success = 1;
	} else {
		reply.success = 0;
	}
	packed_size = store_reply__get_packed_size(&reply);
	packed = malloc(packed_size);
	if (packed == NULL) {
		store__free_unpacked(request, NULL);
		return 0;
	}
	ret = store_reply__pack(&reply, packed);
	assert(ret == packed_size);
	ret = write_package(from, packed, packed_size);
	free(packed);
	if (ret != 0) {
		store__free_unpacked(request, NULL);
		return 0;
	}
	/* update node info */
	ret = extract_kad_nodes(&request->self, 1, &n);
	store__free_unpacked(request, NULL);
	if (ret != 0) {
		return 0;
	}
	update_table_relay(n);
	free_kad_node_info(n);
	return 0;
}
