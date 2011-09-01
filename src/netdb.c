#include "netdb.h"
#include "tunnel.h"

int
validate_signed_routing_table_entry(const SignedRoutingTableEntry *srte)
{
	struct X509_flat routing_certificate_flat;
	X509 *routing_certificate;
	EVP_PKEY *key;
	int ret;
	cleanup_stack_init;

	if (srte->packed_routing_table_entry.data == NULL){
		return -1;
	}
	if (srte->routing_certificate_flat.data == NULL){
		return -1;
	}
	if (srte->signature.data == NULL){
		return -1;
	}
	routing_certificate_flat.data = srte->routing_certificate_flat.data;
	routing_certificate_flat.len = srte->routing_certificate_flat.len;
	routing_certificate = read_x509_from_x509_flat(&routing_certificate_flat);
	if (routing_certificate == NULL) {
		return -1;
	}
	cleanup_stack_push(X509_free, routing_certificate);
	key = X509_get_pubkey(routing_certificate);

	ret = check_signed_data(srte->signature.data,
							srte->signature.len,
							srte->packed_routing_table_entry.data,
							srte->packed_routing_table_entry.len,
							key);

	if (ret != 0) {
		printf("signature failed for routing entry\n");
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_free_all();
	return 0;
}

static int
validate_routing_table_entry(const RoutingTableEntry *r, const struct in6_addr *ap_adress)
{
	uint32_t i;
	if (r->ap_adress.data == NULL) {
		return -1;
	}
	if (r->ap_adress.len != 16) {
		return -1;
	}
	if (ap_adress != NULL) {
		if (memcmp(r->ap_adress.data,
				   ap_adress->s6_addr,
				   sizeof(ap_adress->s6_addr))) {
			return -1;
		}
	}
	if (r->n_ip_adresses != r->n_ports) {
		return -1;
	}
	if (r->n_ip_adresses < 1) {
		return -1;
	}
	for (i = 0; i < r->n_ip_adresses; i++) {
		if (r->ports[i] >> 16) {
			return -1;
		}
		if (r->ip_adresses[i] == NULL) {
			return -1;
		}
	}
	return 0;
}

/* static int */
/* validate_routing_entry_no_port(const RoutingTableEntry *r) */
/* { */
/* 	uint32_t i; */
/* 	if (r->ap_adress.data == NULL) { */
/* 		return -1; */
/* 	} */
/* 	if (r->ap_adress.len != 16) { */
/* 		return -1; */
/* 	} */
/* 	if (r->n_ip_adresses < 1) { */
/* 		return -1; */
/* 	} */
/* 	for (i = 0; i < r->n_ip_adresses; i++) { */
/* 		if (r->ip_adresses[i] == NULL) { */
/* 			return -1; */
/* 		} */
/* 	} */
/* 	return 0; */
/* } */

int register_my_node_in_the_network(char *ip, uint8_t *communicationcertificate, uint8_t *path_building_certificate);
int extend_ap_adress_lease(struct in6_addr *ap_adress, uint8_t *signed_lease_request, uint8_t *routing_certificate);

RoutingTableEntry *
unpack_verify_srte(uint8_t *data, size_t len, const struct in6_addr *ap_adress)
{
	SignedRoutingTableEntry *srte;
	RoutingTableEntry *rte;
	int ret;

	assert(data);
	assert(len);
	srte = signed_routing_table_entry__unpack(NULL, len, data);
	if (srte == NULL) {
		return NULL;
	}
	ret = validate_signed_routing_table_entry(srte);
	if (ret != 0) {
		signed_routing_table_entry__free_unpacked(srte, NULL);
		return NULL;
	}
	rte = routing_table_entry__unpack(NULL,
                                      srte->packed_routing_table_entry.len,
                                      srte->packed_routing_table_entry.data);
	signed_routing_table_entry__free_unpacked(srte, NULL);
	if (rte == NULL) {
		return NULL;
	}
	ret = validate_routing_table_entry(rte, ap_adress);
	if (ret != 0) {
		routing_table_entry__free_unpacked(rte, NULL);
		return NULL;
	}
	return rte;
}
int
get_entry_nodes_for_ap_adress(char ***ip_adresses, uint16_t **ports, int *num, const struct in6_addr *ap_adress)
{
	RoutingTableEntry *rte;
	uint8_t hash[SHA_DIGEST_LENGTH], *data;
	uint32_t i;
	size_t len;
	char **iip_adresses;
	uint16_t *iports;
	int ret;
	SHA1(ap_adress->s6_addr, sizeof (ap_adress->s6_addr), hash);
	ret = kad_find(hash, &data, &len);
	if (ret != 0) {
		return -1;
	}
	rte = unpack_verify_srte(data, len, ap_adress);
	if (rte == NULL) {
		return -1;
	}
	iip_adresses = malloc (rte->n_ip_adresses * sizeof (char *));
	if (iip_adresses == NULL) {
		routing_table_entry__free_unpacked(rte, NULL);
		return -1;
	}
	iports = malloc (rte->n_ip_adresses * sizeof (uint16_t));
	if (iports == NULL) {
		free(iip_adresses);
		routing_table_entry__free_unpacked(rte, NULL);
		return -1;
	}
	for (i = 0; i < rte->n_ip_adresses; i++) {
		iip_adresses[i] = strdup(rte->ip_adresses[i]);
		iports[i] = rte->ports[i];
	}
	*ports = iports;
	*ip_adresses = iip_adresses;
	*num = rte->n_ip_adresses;
	routing_table_entry__free_unpacked(rte, NULL);
	return 0;
}

static struct packed_msg *
perform_anonymous_rpc(const struct config *config,
                      AnonymizedRpc * rpc)
{
	uint8_t buf[4];
	struct path *path;
	struct tunnel *t;
	int ret;
	uint32_t len;
	struct packed_msg *packed_msg;

	cleanup_stack_init;
	assert(config);
	assert(rpc);

	path = construct_reserve_ap_path(config, rpc);
	if (path == NULL) {
		return NULL;
	}
	cleanup_stack_push(free_path, path);
	t = create_ap_reservation_tunnel(path);
	if (t == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free_tunnel, t);
	ret = tunnel_read(t, buf, sizeof(uint32_t));
	if (ret == -1) {
		cleanup_stack_free_all();
		return NULL;
	}
	len = deserialize_32_t(buf);
	packed_msg = malloc(sizeof (struct packed_msg));
	packed_msg->len = len;
	packed_msg->data = malloc(packed_msg->len);
	if (packed_msg->data == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = tunnel_read(t, packed_msg->data, packed_msg->len);
	if (ret == -1) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_free_all();
	return packed_msg;
}

int
publish_routing_table_entry(const struct config *config,
							RoutingTableEntry *rte)
{
	AnonymizedRpc rpc;
	StoreReply *reply;
	size_t len, ret_len;
	uint8_t *data;
	int ret;
	SignedRoutingTableEntry srte;
	struct packed_msg *packed_reply;
	cleanup_stack_init;
	assert(config);
	assert(rte);
	assert(config->private_routing_key);

	signed_routing_table_entry__init(&srte);
	len = routing_table_entry__get_packed_size(rte);
	srte.packed_routing_table_entry.len = len;
	data = malloc(len);
	if (data == NULL) {
		return -1;
	}
	ret_len = routing_table_entry__pack(rte, data);
	if (ret_len != len) {
		return -1;
	}
	srte.packed_routing_table_entry.data = data;
	cleanup_stack_push(free, srte.packed_routing_table_entry.data);

	srte.routing_certificate_flat.data = config->routing_certificate_flat->data;
	srte.routing_certificate_flat.len = config->routing_certificate_flat->len;

	/* sign rte */
	len = BN_num_bytes(config->private_routing_key->pkey.rsa->n);
	srte.signature.len = len;
	data = malloc(srte.signature.len);
	if (data == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
    srte.signature.data = data;
	cleanup_stack_push(free, srte.signature.data);
	ret = sign_data(srte.signature.data,
					srte.packed_routing_table_entry.data,
					srte.packed_routing_table_entry.len,
					config->private_routing_key);

	if (ret == -1) {
		cleanup_stack_free_all();
		return -1;
	}

	anonymized_rpc__init(&rpc);
	rpc.type = ANONYMOUS_STORE;

	len = signed_routing_table_entry__get_packed_size(&srte);
	rpc.data.len = len;
	data = malloc(len);
	if (data == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	ret_len = signed_routing_table_entry__pack(&srte, data);
	rpc.data.data = data;
	cleanup_stack_push(free, rpc.data.data);
	if (len != ret_len) {
		cleanup_stack_free_all();
		return -1;
	}

	packed_reply = perform_anonymous_rpc(config, &rpc);
	if (packed_reply == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(packed_msg_free, packed_reply);

	reply = store_reply__unpack(NULL, packed_reply->len, packed_reply->data);
	if (reply == NULL){
		cleanup_stack_free_all();
		return -1;
	}
	if (reply->success) {
		store_reply__free_unpacked(reply, NULL);
		cleanup_stack_free_all();
		return -1;
	}
	store_reply__free_unpacked(reply, NULL);
	cleanup_stack_free_all();
	return 0;
}

int
reserve_new_ap_adress(const struct config *config, struct in6_addr *ap)
{
	uint8_t hash[SHA_DIGEST_LENGTH];
	static uint8_t ap_prefix[] = AP_PREFIX;
	AnonymizedRpc rpc;
	FindValueReply *reply;
	struct packed_msg *packed_reply;
	cleanup_stack_init;
	assert(config);
	assert(ap);

	/* randomly choose AP locally */
	assert(sizeof (ap_prefix) < sizeof (ap->s6_addr));
	memcpy(ap->s6_addr, ap_prefix, sizeof (ap_prefix));
	rand_bytes(ap->s6_addr + sizeof (ap_prefix),
               sizeof (ap->s6_addr) - sizeof (ap_prefix));

    /* Test if it AP already exists */
    /* a collision should almost never happen. */
    /* If it does it quite likely a bug. */
	SHA1(ap->s6_addr, sizeof(ap), hash);
	anonymized_rpc__init(&rpc);
	rpc.data.len = SHA_DIGEST_LENGTH;
	rpc.data.data = hash;
	rpc.type = ANONYMOUS_FIND;

	packed_reply = perform_anonymous_rpc(config, &rpc);
	if (packed_reply == NULL) {
		return -1;
	}
	cleanup_stack_push(packed_msg_free, packed_reply);
	/* check that the ap does not already exist */
	reply = find_value_reply__unpack(NULL, packed_reply->len, packed_reply->data);
	if (reply == NULL){
		cleanup_stack_free_all();
		return -1;
	}
	if (reply->success) {
		find_value_reply__free_unpacked(reply, NULL);
		cleanup_stack_free_all();
		return -1;
	}
	find_value_reply__free_unpacked(reply, NULL);
	cleanup_stack_free_all();
	return 0;
}

/* int */
/* update_routing_table_entry(const struct in6_addr *ap_adress, struct rte *signed_routing_entry, uint16_t port, uint8_t *routing_certificate) */
/* { */
/* 	int ret; */
/* 	RoutingTableEntry *re; */
/* 	uint8_t key[SHA_DIGEST_LENGTH]; */
/* 	/\* FIXME routing cert *\/ */
/* 	(void) routing_certificate; */
/* 	re = routing_table_entry__unpack(NULL, signed_routing_entry->len, signed_routing_entry->data); */
/* 	if (re == NULL) { */
/* 		return -1; */
/* 	} */
/* 	ret = validate_routing_entry_no_port(re); */
/* 	if (ret != 0) { */
/* 		routing_table_entry__free_unpacked(re, NULL); */
/* 		return -1; */
/* 	} */
/* 	/\*XXX in the end the port should not come from the entrynode but from */
/* 	 * the anonymized node - which means it has to be communicated back to */
/* 	 * the anonymized node in some way, so it can be signed by him as a */
/* 	 * total*\/ */
/* 	re->n_ports = 1; */
/* 	re->ports = malloc(sizeof (uint32_t)); */
/* 	if (re->ports == NULL) { */
/* 		routing_table_entry__free_unpacked(re, NULL); */
/* 		return -1; */
/* 	} */
/* 	re->ports[0] = port; */
/* 	free(signed_routing_entry->data); */
/* 	signed_routing_entry->len = routing_table_entry__get_packed_size(re); */
/* 	signed_routing_entry->data = malloc(signed_routing_entry->len); */
/* 	if (signed_routing_entry->data == NULL) { */
/* 		routing_table_entry__free_unpacked(re, NULL); */
/* 		return -1; */
/* 	} */
/* 	ret = routing_table_entry__pack(re, signed_routing_entry->data); */
/* 	routing_table_entry__free_unpacked(re, NULL); */
/* 	assert((uint32_t) ret == signed_routing_entry->len); */
/* 	SHA1(ap_adress->s6_addr, sizeof(ap_adress->s6_addr), key); */
/* 	ret = kad_store(key, signed_routing_entry->data, signed_routing_entry->len); */
/* 	if (ret == -1) { */
/* 		return -1; */
/* 	} */
/* 	return 0; */
/* } */

int
get_random_node_ip_adresses(char **adresses, uint16_t *ports, X509 **communication_certificates, X509 **path_building_certificates, int num)
{
	int i;
	struct kad_node_list *list;
	struct kad_node_info *n;
	assert(adresses);
	assert(ports);
	assert(communication_certificates);
	assert(path_building_certificates);
	while (1) {
		list = get_n_nodes(num);
		if (list == NULL || list->nentries < num) {
			if (list != NULL) {
				printf("nentries was %d\n", list->nentries);
				free_kad_node_list(list);
			} else {
				printf("nentries was 0\n");
			}
			poll(NULL, 0, 1000);
			continue;
		}
		break;
	}
	n = list->list.next;
	for (i = 0; i < num; i++) {
		adresses[i] = n->ip;
		n->ip = NULL;
		communication_certificates[i] = n->cert;
		n->cert = NULL;
		path_building_certificates[i] = n->pbc;
		n->pbc = NULL;
		ports[i] = n->port;
		n = n->next;
	}
	free_kad_node_list(list);
	return num;
}

void
update_netdb_publishing(RoutingTableEntry *rte)
{
	update_kad_publishing(rte);
}
