#include "config.h"

static struct X509_flat *
read_cert(char *path)
{
	struct X509_flat *x;
	x = read_x509_from_file_flat(path);
	if (x == NULL) {
		return NULL;
	}
	return x;
}

static void
parse_config(xmlDocPtr doc, xmlNodePtr cur, struct config *config)
{
	xmlChar *key = NULL;
	size_t keylen = 0;
	FILE *fh;
	RSA *x;
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "ip")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			keylen = strlen((char *) key);
			if (keylen < SIZE_MAX) {
				config->ip = malloc(keylen + 1);
			}
			if (config->ip == NULL) {
				printf("malloc failed\n");
				exit(EXIT_FAILURE);
			}
			strncpy(config->ip, (char *) key, keylen + 1);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "kadnodefile")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			keylen = strlen((char *) key);
			if (keylen < SIZE_MAX) {
				config->kad_node_file = malloc(keylen + 1);
			}
			if (config->kad_node_file == NULL) {
				printf("malloc failed\n");
				exit(EXIT_FAILURE);
			}
			strncpy(config->kad_node_file, (char *) key,
			        keylen + 1);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "kaddata")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			keylen = strlen((char *) key);
			if (keylen < SIZE_MAX) {
				config->kad_data_dir = malloc(keylen + 1);
			}
			if (config->kad_data_dir == NULL) {
				printf("malloc failed\n");
				exit(EXIT_FAILURE);
			}
			strncpy(config->kad_data_dir, (char *) key,
			        keylen + 1);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "port")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->port = (unsigned short) atoi((char *) key);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "xnodes")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->nxnodes = (int) atoi((char *) key);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "ynodes")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->nynodes = (int) atoi((char *) key);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "keys")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->nkeys = (int) atoi((char *) key);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "communicationcertificate")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->communication_certificate_flat = read_cert((char *) key);
			assert(config->communication_certificate_flat);
			config->communication_certificate = read_x509_from_x509_flat(config->communication_certificate_flat);
			assert(config->communication_certificate);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "constructioncertificate")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->construction_certificate_flat = read_cert((char *) key);
			assert(config->construction_certificate_flat);
			config->construction_certificate = read_x509_from_x509_flat(config->construction_certificate_flat);
			assert(config->construction_certificate);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "routingcertificate")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			config->routing_certificate_flat = read_cert((char *) key);
			assert(config->routing_certificate_flat);
			config->routing_certificate = read_x509_from_x509_flat(config->routing_certificate_flat);
			assert(config->routing_certificate);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "communicationcertificateprivate")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			fh = fopen((char *) key, "r");
			if (fh == NULL) {
				printf("fopen failed\n");
				exit(EXIT_FAILURE);
			}
			x = PEM_read_RSAPrivateKey(fh, NULL, NULL, NULL);
			assert(x);
			config->private_communication_key = EVP_PKEY_new();
			assert(config->private_communication_key);
			EVP_PKEY_set1_RSA(config->private_communication_key, x);
			fclose(fh);
			RSA_free(x);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "constructioncertificateprivate")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			fh = fopen((char *) key, "r");
			if (fh == NULL) {
				printf("fopen failed\n");
				exit(EXIT_FAILURE);
			}
			x = PEM_read_RSAPrivateKey(fh, NULL, NULL, NULL);
			assert(x);
			config->private_construction_key = EVP_PKEY_new();
			assert(config->private_construction_key);
			EVP_PKEY_set1_RSA(config->private_construction_key, x);
			fclose(fh);
			RSA_free(x);
			xmlFree(key);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "routingcertificateprivate")) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			fh = fopen((char *) key, "r");
			if (fh == NULL) {
				printf("fopen failed\n");
				exit(EXIT_FAILURE);
			}
			x = PEM_read_RSAPrivateKey(fh, NULL, NULL, NULL);
			assert(x);
			config->private_routing_key = EVP_PKEY_new();
			assert(config->private_routing_key);
			EVP_PKEY_set1_RSA(config->private_routing_key, x);
			fclose(fh);
			RSA_free(x);
			xmlFree(key);
		}
		cur = cur->next;
	}
}

void
read_config(char *path, struct config *config)
{
	xmlDocPtr doc;
	xmlNodePtr root_element;
	bzero(config, sizeof (struct config));
	doc = xmlReadFile(path, NULL, 0);
	if (doc == NULL) {
		printf("failed to pasre config\n");
		exit(EXIT_FAILURE);
	}
	root_element = xmlDocGetRootElement(doc);
	if (xmlStrcmp(root_element->name, (const xmlChar *) "phantomconfig")) {
		printf("This is not a phantom config file");
		exit(EXIT_FAILURE);
	}
	parse_config(doc, root_element, config);
	xmlFreeDoc(doc);
	assert(config->ip);
	assert(config->kad_node_file);
	assert(config->kad_data_dir);
	assert(config->port);
	assert(config->nxnodes);
	assert(config->nynodes);
	assert(config->nkeys);
	assert(config->construction_certificate_flat);
	assert(config->communication_certificate_flat);
	assert(config->routing_certificate_flat);
	assert(config->construction_certificate);
	assert(config->communication_certificate);
	assert(config->routing_certificate);
	assert(config->private_construction_key);
	assert(config->private_communication_key);
	assert(config->private_routing_key);
}

void
free_config(struct config *config)
{
	free(config->ip);
	free_X509_flat(config->communication_certificate_flat);
	free_X509_flat(config->construction_certificate_flat);
	free_X509_flat(config->routing_certificate_flat);
	X509_free(config->communication_certificate);
	X509_free(config->construction_certificate);
	X509_free(config->routing_certificate);
	EVP_PKEY_free(config->private_construction_key);
	EVP_PKEY_free(config->private_communication_key);
	EVP_PKEY_free(config->private_routing_key);
	free(config->kad_node_file);
	free(config->kad_data_dir);
}
