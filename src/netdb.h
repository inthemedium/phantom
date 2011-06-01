#ifndef __HAVE_NET_DB_H__
#define __HAVE_NET_DB_H__

#include <stdio.h>
#include <sys/utsname.h>
#include <string.h>
#include "node_info.h"
#include "x509_flat.h"
#include "config.h"
#include "kademlia.h"
#include "conn_ctx.h"
#include "setuppackage.pb-c.h"

/* API */
int register_my_node_in_the_network(char *ip, uint8_t *communicationcertificate, uint8_t *path_building_certificate);
int reserve_new_ap_adress(const struct config *config, struct in6_addr *ap);
int extend_ap_adress_lease(struct in6_addr *ap_adress, uint8_t *signed_lease_request, uint8_t *routing_certificate);
int update_routing_table_entry(const struct in6_addr *ap_adress, struct rte *signed_routing_entry, uint16_t port, uint8_t *routing_certificate);
int get_random_node_ip_adresses(char **adresses, uint16_t *ports, X509 **communication_certificates, X509 **path_building_certificates, int num);
int get_entry_nodes_for_ap_adress(char ***ip_adresses, uint16_t **ports, int *num, const struct in6_addr *ap_adress);
#endif
