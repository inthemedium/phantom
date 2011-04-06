#include "netdb.h"
#include "tunnel.h"

static int
validate_routing_entry(const RoutingTableEntry *r, const struct in6_addr *ap_adress)
{
	uint32_t i;
	if (r->ap_adress.data == NULL) {
		return -1;
	}
	if (r->ap_adress.len != 16) {
		return -1;
	}
	if (memcmp(r->ap_adress.data, ap_adress->s6_addr, sizeof(ap_adress->s6_addr))) {
		return -1;
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

static int
validate_routing_entry_no_port(const RoutingTableEntry *r)
{
	uint32_t i;
	if (r->ap_adress.data == NULL) {
		return -1;
	}
	if (r->ap_adress.len != 16) {
		return -1;
	}
	if (r->n_ip_adresses < 1) {
		return -1;
	}
	for (i = 0; i < r->n_ip_adresses; i++) {
		if (r->ip_adresses[i] == NULL) {
			return -1;
		}
	}
	return 0;
}

int register_my_node_in_the_network(char *ip, uint8_t *communicationcertificate, uint8_t *path_building_certificate);
int extend_ap_adress_lease(struct in6_addr *ap_adress, uint8_t *signed_lease_request, uint8_t *routing_certificate);

int
get_entry_nodes_for_ap_adress(char ***ip_adresses, uint16_t **ports, int *num, const struct in6_addr *ap_adress)
{
	RoutingTableEntry *re;
	uint8_t hash[SHA_DIGEST_LENGTH], *re_data;
	uint32_t i;
	size_t re_len;
	char **iip_adresses;
	uint16_t *iports;
	int ret;
	SHA1(ap_adress->s6_addr, sizeof (ap_adress->s6_addr), hash);
	ret = kad_find(hash, &re_data, &re_len);
	if (ret != 0) {
		return -1;
	}
	re = routing_table_entry__unpack(NULL, re_len, re_data);
	free(re_data);
	if (re == NULL) {
		return -1;
	}
	ret = validate_routing_entry(re, ap_adress);
	if (ret != 0) {
		routing_table_entry__free_unpacked(re, NULL);
		return -1;
	}
	iip_adresses = malloc (re->n_ip_adresses * sizeof (char *));
	if (iip_adresses == NULL) {
		routing_table_entry__free_unpacked(re, NULL);
		return -1;
	}
	iports = malloc (re->n_ip_adresses * sizeof (uint16_t));
	if (iports == NULL) {
		free(iip_adresses);
		routing_table_entry__free_unpacked(re, NULL);
		return -1;
	}
	for (i = 0; i < re->n_ip_adresses; i++) {
		iip_adresses[i] = strdup(re->ip_adresses[i]);
		iports[i] = re->ports[i];
	}
	*ports = iports;
	*ip_adresses = iip_adresses;
	*num = re->n_ip_adresses;
	routing_table_entry__free_unpacked(re, NULL);
	return 0;
}

int
reserve_new_ap_adress(const struct config *config, struct in6_addr *ap)
{
	struct path *path;
	struct tunnel *t;
	int ret;
	assert(config);
	assert(ap);
	path = construct_reserve_ap_path(config);
	if (path == NULL) {
		return -1;
	}
	t = create_ap_reservation_tunnel(path);
	if (t == NULL) {
		free_path(path);
		return -1;
	}
	ret = tunnel_read(t, ap->s6_addr, sizeof (ap->s6_addr));
	free_tunnel(t);
	free_path(path);
	if (ret == -1) {
		return -1;
	}
	return 0;
}

int
update_routing_table_entry(const struct in6_addr *ap_adress, struct rte *signed_routing_entry, uint16_t port, uint8_t *routing_certificate)
{
	int ret;
	RoutingTableEntry *re;
	uint8_t key[SHA_DIGEST_LENGTH];
	/* FIXME routing cert */
	(void) routing_certificate;
	re = routing_table_entry__unpack(NULL, signed_routing_entry->len, signed_routing_entry->data);
	if (re == NULL) {
		return -1;
	}
	ret = validate_routing_entry_no_port(re);
	if (ret != 0) {
		routing_table_entry__free_unpacked(re, NULL);
		return -1;
	}
	/*XXX in the end the port should not come from the entrynode but from
	 * the anonymized node - which means it has to be communicated back to
	 * the anonymized node in some way, so it can be signed by him as a
	 * total*/
	re->n_ports = 1;
	re->ports = malloc(sizeof (uint32_t));
	if (re->ports == NULL) {
		routing_table_entry__free_unpacked(re, NULL);
		return -1;
	}
	re->ports[0] = port;
	free(signed_routing_entry->data);
	signed_routing_entry->len = routing_table_entry__get_packed_size(re);
	signed_routing_entry->data = malloc(signed_routing_entry->len);
	if (signed_routing_entry->data == NULL) {
		routing_table_entry__free_unpacked(re, NULL);
		return -1;
	}
	ret = routing_table_entry__pack(re, signed_routing_entry->data);
	routing_table_entry__free_unpacked(re, NULL);
	assert((uint32_t) ret == signed_routing_entry->len);
	SHA1(ap_adress->s6_addr, sizeof(ap_adress->s6_addr), key);
	ret = kad_store(key, signed_routing_entry->data, signed_routing_entry->len);
	if (ret == -1) {
		return -1;
	}
	return 0;
}

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
