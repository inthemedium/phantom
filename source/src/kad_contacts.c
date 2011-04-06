#include "kad_contacts.h"

static int
write_contact(FILE *f, struct kad_node_info *contact)
{
	struct X509_flat *cert, *pbc;
	int ret;
	assert(contact);
	ret = fwrite(contact->id, SHA_DIGEST_LENGTH, 1, f);
	if (ret != 1) {
		return -1;
	}
	cert = flatten_X509(contact->cert);
	if (cert == NULL) {
		return -1;
	}
	pbc = flatten_X509(contact->pbc);
	if (pbc == NULL) {
		free_X509_flat(cert);
		return -1;
	}
	ret = fprintf(f, "\n%hi %s %i %i\n", contact->port, contact->ip, cert->len, pbc->len);
	if (ret < 0) {
		free_X509_flat(cert);
		free_X509_flat(pbc);
		return -1;
	}
	ret = fwrite(cert->data, cert->len, 1, f);
	free_X509_flat(cert);
	if (ret != 1) {
		free_X509_flat(pbc);
		return -1;
	}
	ret = fwrite(pbc->data, pbc->len, 1, f);
	free_X509_flat(pbc);
	if (ret != 1) {
		return -1;
	}
	return 0;
}

static int
read_contact(FILE *f, struct kad_node_info *contact)
{
	uint8_t id[SHA_DIGEST_LENGTH];
	struct kad_node_info *new;
	X509 *x, *xp;
	short port;
	char ip[40];
	struct X509_flat cert, pbc;
	int ret;
	assert(f);
	assert(contact);
	ret = fread(id, SHA_DIGEST_LENGTH, 1, f);
	if (ret != 1) {
		return -1;
	}
	ret = fscanf(f, "\n%hi %s %i %i\n", &port, ip, &cert.len, &pbc.len);
	if (ret != 4) {
		printf("fail1\n");
		return -1;
	}
	cert.data = malloc(cert.len);
	if (cert.data == NULL) {
		return -1;
	}
	ret = fread(cert.data, cert.len, 1, f);
	if (ret != 1) {
		free(cert.data);
		return -1;
	}
	x = read_x509_from_x509_flat(&cert);
	free(cert.data);
	if (x == NULL) {
		return -1;
	}
	pbc.data = malloc(pbc.len);
	if (cert.data == NULL) {
		return -1;
	}
	ret = fread(pbc.data, pbc.len, 1, f);
	if (ret != 1) {
		free(pbc.data);
		return -1;
	}
	xp = read_x509_from_x509_flat(&pbc);
	free(pbc.data);
	if (xp == NULL) {
		return -1;
	}
	new = new_kad_node_info(id, ip, port, x, xp);
	X509_free(x);
	X509_free(xp);
	if (new == NULL) {
		return -1;
	}
	LIST_insert(contact, new);
	return 0;
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
