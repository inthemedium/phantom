#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>

#include "helper.h"
#include "kademlia.h"
#include "x509_flat.h"
#include "kad_contacts.h"

static int
write_contact(FILE *f, struct kad_node_info *contact)
{
	struct X509_flat *cert = NULL, *pbc = NULL;
	int ret = -1;
	assert(contact);
	ret = fwrite(contact->id, SHA_DIGEST_LENGTH, 1, f);
	if (ret != 1) {
		ret = -1;
		goto abort;
	}
	cert = flatten_X509(contact->cert);
	pbc = flatten_X509(contact->pbc);
	if (cert == NULL || pbc == NULL) {
		ret = -1;
		goto abort;
	}
	ret = fprintf(f, "\n%hi %s %lu %lu\n",
	              contact->port, contact->ip,
	              (long unsigned) cert->len,
	              (long unsigned) pbc->len);
	if (ret < 0) {
		ret = -1;
		goto abort;
	}
	ret = fwrite(cert->data, cert->len, 1, f);
	if (ret != 1) {
		ret = -1;
		goto abort;
	}
	ret = fwrite(pbc->data, pbc->len, 1, f);
	if (ret != 1) {
		ret = -1;
		goto abort;
	}
	ret = 0;
abort:
	free_X509_flat(cert);
	free_X509_flat(pbc);
	return ret;
}

static int
read_contact(FILE *f, struct kad_node_info *contact)
{
	uint8_t id[SHA_DIGEST_LENGTH];
	struct kad_node_info *new;
	X509 *x = NULL, *xp = NULL;
	short port;
	char ip[40];
	struct X509_flat *cert = NULL, *pbc = NULL;
	int ret = -1;
	assert(f);
	assert(contact);
	ret = fread(id, SHA_DIGEST_LENGTH, 1, f);
	if (ret != 1) {
		ret = -1;
		goto abort;
	}
	cert = new_X509_flat();
	pbc = new_X509_flat();
	if (cert == NULL || pbc == NULL) {
		ret = -1;
		goto abort;
	}
	errno = 0;
	ret = fscanf(f, "\n%hi %s %lu %lu\n",
	             &port, ip,
	             (long unsigned *) &(cert->len),
	             (long unsigned *) &(pbc->len));
	if (ret != 4) {
		if (errno != 0) {
			perror("fscanf");
		}
		ret = -1;
		goto abort;
	}
	if (cert->len != 0
	    && cert->len <= SIZE_MAX/sizeof(*(cert->data))) {
		cert->data = malloc(cert->len*sizeof(*(cert->data)));
	}
	if (cert->data == NULL) {
		ret = -1;
		goto abort;
	}
	ret = fread(cert->data, cert->len, 1, f);
	if (ret != 1) {
		ret = -1;
		goto abort;
	}
	x = read_x509_from_x509_flat(cert);
	if (x == NULL) {
		ret = -1;
		goto abort;
	}
	if (pbc->len != 0
	    && pbc->len <= SIZE_MAX/sizeof(*(pbc->data))) {
		pbc->data = malloc(pbc->len*sizeof(*(pbc->data)));
	}
	if (pbc->data == NULL) {
		ret = -1;
		goto abort;
	}
	ret = fread(pbc->data, pbc->len, 1, f);
	if (ret != 1) {
		ret = -1;
		goto abort;
	}
	xp = read_x509_from_x509_flat(pbc);
	if (xp == NULL) {
		ret = -1;
		goto abort;
	}
	new = new_kad_node_info(id, ip, port, x, xp);
	if (new == NULL) {
		ret = -1;
		goto abort;
	}
	LIST_insert(contact, new);
	ret = 0;
abort:
	free_X509_flat(cert);
	free_X509_flat(pbc);
	if (x != NULL) {
		X509_free(x);
	}
	if (xp != NULL) {
		X509_free(xp);
	}
	return ret;
}

int
restore_contacts(const char *filename, struct kad_node_info *contacts)
{
	FILE *f;
	int ret, cnt;
	assert(filename);
	assert(contacts);
	f = fopen(filename, "r");
	if (f == NULL) {
		return -1;
	}
	LIST_init(contacts);
	cnt = 0;
	while (1) {
		ret = read_contact(f, contacts);
		if (ret != 0) {
			break;
		}
		cnt++;
	}
	fclose(f);
	return (cnt)? 0 : -1;
}

int
save_contacts(const char *filename, struct kad_table *table)
{
	FILE *f;
	int i, ret, cnt;
	struct kad_node_info *help1, *help2;
	assert(table);
	assert(filename);
	f = fopen(filename, "w");
	if (f == NULL) {
		return -1;
	}
	cnt = 0;
	for (i = 0; i < NBUCKETS; i++) {
		pthread_mutex_lock(&table->bucket_mutexes[i]);
		LIST_for_all(&table->buckets[i], help1, help2) {
			ret = write_contact(f, help1);
			if (ret != 0) {
				pthread_mutex_unlock(&table->bucket_mutexes[i]);
				fclose(f);
				return -1;
			}
			cnt++;
		}
		pthread_mutex_unlock(&table->bucket_mutexes[i]);
	}
	printf("saved %d contacts\n", cnt);
	fclose(f);
	return 0;
}
