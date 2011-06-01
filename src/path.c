#include "path.h"
#include "server.h"

static int
add_routing_table_entry(SetupPackage *s, struct in6_addr *ap_adress, char *const *ips, int nips)
{
	int i;
	s->rte = malloc(sizeof (RoutingTableEntry));
	if (s->rte == NULL) {
		return -1;
	}
	routing_table_entry__init(s->rte);
	s->rte->ap_adress.data = ap_adress->s6_addr;
	assert(sizeof (ap_adress->s6_addr) == 16);
	s->rte->ap_adress.len = sizeof (ap_adress->s6_addr);
	s->rte->n_ip_adresses = nips;
	s->rte->ip_adresses = malloc (nips * sizeof (char *));
	if (s->rte->ip_adresses == NULL) {
		free(s->rte);
		return -1;
	}
	if (s->rte->ip_adresses == NULL) {
		free(s->rte->ip_adresses);
		free(s->rte);
		return -1;
	}
	for (i = 0; i < nips; i++) {
		s->rte->ip_adresses[i] = ips[i];
	}
	return 0;
}

static void
pad_key(const uint8_t *key, int len, uint8_t *out, int wantlen)
{
	int i;
	assert(wantlen > len);
	for (i = 0; i < wantlen / len; i++) {
		memcpy(out + len * i, key, len);
	}
	memcpy(out + i * len, key, wantlen - i * len);
}

static  struct xkeys *
generate_conn_keys(int nkeys, const uint8_t *basekey, const uint8_t *salt)
{
	int i;
	uint8_t tmp[SYMMETRIC_CIPHER_KEY_LEN];
	struct xkeys *keys;
	cleanup_stack_init;
	assert(SYMMETRIC_CIPHER_IV_LEN <= SYMMETRIC_CIPHER_KEY_LEN);
	keys = malloc(sizeof (struct xkeys));
	if (keys == NULL) {
		return NULL;
	}
	cleanup_stack_push(free, keys);
	keys->nkeys = nkeys;
	keys->ivs = malloc(nkeys * SYMMETRIC_CIPHER_IV_LEN);
	if (keys->ivs == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, keys->ivs);
	keys->keys = malloc(nkeys * SYMMETRIC_CIPHER_KEY_LEN);
	if (keys->keys == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, keys->keys);
	memcpy(tmp, basekey, SYMMETRIC_CIPHER_KEY_LEN);
	for (i = 0; i < nkeys; i++) {
		PKCS5_PBKDF2_HMAC_SHA1((char *) tmp, SYMMETRIC_CIPHER_KEY_LEN, salt, SYMMETRIC_CIPHER_KEY_LEN, PBKDF2_STEPS, SYMMETRIC_CIPHER_KEY_LEN, keys->keys + SYMMETRIC_CIPHER_KEY_LEN * i);
		memcpy(tmp, keys->keys + SYMMETRIC_CIPHER_KEY_LEN * i, SYMMETRIC_CIPHER_KEY_LEN);
	}
	for (i = 0; i < nkeys; i++) {
		PKCS5_PBKDF2_HMAC_SHA1((char *) tmp, SYMMETRIC_CIPHER_IV_LEN, salt, SYMMETRIC_CIPHER_IV_LEN, PBKDF2_STEPS, SYMMETRIC_CIPHER_IV_LEN, keys->ivs + SYMMETRIC_CIPHER_IV_LEN * i);
		memcpy(tmp, keys->ivs + SYMMETRIC_CIPHER_IV_LEN * i, SYMMETRIC_CIPHER_IV_LEN);
	}
	/* keep allocs in case of success */
	return keys;
}

static int
contains(const uint32_t *haystack, uint32_t needle, size_t nmemb)
{
	int cnt = 0;
	while (--nmemb) {
		if (haystack[nmemb] == needle) {
			cnt++;
		}
	}
	return cnt;
}

static void
delete_nodes(struct node_info *array, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (array[i].construction_certificate != NULL) {
			X509_free(array[i].construction_certificate);
		}
		if (array[i].communication_certificate != NULL) {
			X509_free(array[i].communication_certificate);
		}
		if (array[i].construction_certificate_flat != NULL) {
			free_X509_flat(array[i].construction_certificate_flat);
		}
		if (array[i].communication_certificate_flat != NULL) {
			free_X509_flat(array[i].communication_certificate_flat);
		}
		if (array[i].ip != NULL) {
			free(array[i].ip);
		}
	}
	free(array);
}

static struct path *
new_path(void)
{
	struct path *p = calloc(1, sizeof (struct path));
	if (p == NULL) {
		return NULL;
	}
	return p;
}

static void
delete_struct_setup_path2(struct setup_path *path, int save_conn)
{
	int i;
	if (path->nodes != NULL) {
		delete_nodes(path->nodes, path->nnodes);
	}
	if (path->construction_certificate != NULL) {
		RSA_free(path->construction_certificate);
	}
	if (path->sizes != NULL) {
		free(path->sizes);
	}
	if (path->contents != NULL) {
		for (i = 0; i < path->nnodes; i++) {
			if (path->contents[i] != NULL) {
				free(path->contents[i]);
			}
		}
		free(path->contents);
	}
	for (i = 0; i < path->nnodes; i++) {
		if (path->sps[i].dummies != NULL) {
			free(path->sps[i].dummies);
		}
	}
	if (path->sps != NULL) {
		free(path->sps);
	}
	if (path->ssl_conn != NULL && (! save_conn)) {
		free_ssl_connection(path->ssl_conn);
	}
	if (path->construction_certificate_data != NULL) {
		free(path->construction_certificate_data);
	}
	free(path);
}

static void
delete_struct_setup_path(struct setup_path *path)
{
	delete_struct_setup_path2(path, 0);
}

static struct setup_path *
create_struct_setup_path(const struct config *config, int want_entrypath, int reserve_ap)
{
	int i, j, ret;
	struct setup_path *p = calloc(1, sizeof (struct setup_path));
	if (p == NULL) {
		free(p);
		return NULL;
	}
	p->reserve_ap_adress = reserve_ap;
	p->nxnodes = config->nxnodes;
	p->nynodes = config->nynodes;
	p->nnodes = config->nynodes + config->nxnodes;
	p->entrypath = want_entrypath;
	if (! reserve_ap) {
		p->routing_certificate = config->routing_certificate;
		p->routing_certificate_flat = config->routing_certificate_flat;
		bzero(p->ap.s6_addr, 16);
		ret = reserve_new_ap_adress(config, &p->ap);
		if (ret != 0) {
			free(p);
			return NULL;
		}
	}
	p->nodes = calloc(p->nnodes, sizeof (struct node_info));
	if (p->nodes == NULL) {
		delete_struct_setup_path(p);
		return NULL;
	}
	p->sizes = calloc(p->nnodes, 4);
	if (p->sizes == NULL) {
		delete_struct_setup_path(p);
		return NULL;
	}
	p->contents = calloc(p->nnodes, sizeof (uint8_t *));
	if (p->contents == NULL) {
		delete_struct_setup_path(p);
		return NULL;
	}
	p->sps = calloc(p->nnodes, sizeof (struct setup_package));
	if (p->sps == NULL)  {
		delete_struct_setup_path(p);
		return NULL;
	}
	assert(MIN_DUMMIES <= MAX_DUMMIES);
	for (i = 0; i < p->nnodes; i++) {
		p->sps[i].ndummies = rand_range(MIN_DUMMIES, MAX_DUMMIES);
		p->sps[i].dummies = malloc(p->sps[i].ndummies * sizeof (struct dummy_package));
		if (p->sps[i].dummies == NULL) {
			delete_struct_setup_path(p);
			return NULL;
		}
		for (j = 0; j < p->sps[i].ndummies; j++) {
			rand_bytes(p->sps[i].dummies[j].seed, SYMMETRIC_CIPHER_KEY_LEN);
		}
	}
	return p;
}

static int
get_nodes_from_db(struct node_info *nodes, int num)
{
	int i, ret;
	char **ips;
	uint16_t *ports;
	X509 **ccs, **pbcs;
	cleanup_stack_init;
	ips = malloc(num * sizeof (char *));
	if (ips == NULL) {
		return -1;
	}
	cleanup_stack_push(free, ips);
	ports = malloc(num * sizeof (uint16_t));
	if (ports == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free, ports);
	ccs = malloc(num * sizeof (X509 *));
	if (ccs == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free, ccs);
	pbcs = malloc(num * sizeof(X509 *));
	if (pbcs == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free, pbcs);
	ret = get_random_node_ip_adresses(ips, ports, ccs, pbcs, num);
	assert(ret == num);
	for (i = 0; i < num; i++) {
		nodes[i].ip = ips[i];
		nodes[i].communication_certificate = ccs[i];
		nodes[i].construction_certificate = pbcs[i];
		nodes[i].communication_certificate_flat = flatten_X509(ccs[i]);
		nodes[i].construction_certificate_flat = flatten_X509(pbcs[i]);
		nodes[i].port = ports[i];
	}
	cleanup_stack_free_all();
	return 0;
}

static void
build_xy_path(struct setup_path *path)
{
	int i, x, occurences, cnt, excessynodes, *indices;
	excessynodes = path->nynodes - 2 * path->nxnodes;
	indices = alloca(excessynodes * sizeof (int));
	randomize_array(path->nodes, path->nnodes, sizeof (struct node_info));
	for (i = 0; i < excessynodes; i++) {
		indices[i] = rand_range(0, path->nxnodes);
	}
	cnt = 0;
	/* begin with a single y node */
	path->nodes[cnt++].flags |= Y_NODE;
	x = 0;
	/* intermix x and y nodes in the middle */
	while(x < path->nxnodes) {
		occurences = contains((const uint32_t *) indices, (uint32_t) x, excessynodes);
		if (occurences) {
			/* insert randomly many excess ynodes */
			for (i = 0; i < occurences; i++) {
				path->nodes[cnt++].flags |= Y_NODE;
			}
		}
		/* insert one xnode followed by one ynode*/
		path->nodes[cnt++].flags |= X_NODE;
		x++;
		path->nodes[cnt++].flags |= Y_NODE;
	}
	/* end with the rest of the ynodes */
	while (cnt < path->nnodes) {
		path->nodes[cnt++].flags |= Y_NODE;
	}
	assert(x == path->nxnodes && cnt == path->nnodes);
	/* reverse whole path with a 50% chance */
	path->is_reverse_path = rand_range(0, 2);
	if (path->is_reverse_path) {
		reverse_array(path->nodes, path->nnodes, sizeof (struct node_info));
		for (i = 0; i < path->nnodes; i++) {
			if (path->nodes[i].flags & X_NODE) {
				path->nodes[i].flags |= T_NODE;
				if (path->entrypath) {
					path->entry_ip = path->nodes[i].ip;
					path->nodes[i].flags |= ENTRY_NODE;
				} else if (path->reserve_ap_adress) {
					path->nodes[i].flags |= RESERVE_AP;
				}
				break;
			}
		}
	} else {
		for (i = 0; i < path->nnodes; i++) {
			if (path->nodes[path->nnodes - 1 - i].flags & X_NODE) {
				path->nodes[path->nnodes - 1 - i].flags |= T_NODE;
				if (path->entrypath) {
					path->nodes[path-> nnodes - 1 - i].flags |= ENTRY_NODE;
					path->entry_ip = path->nodes[path->nnodes - 1 - i].ip;
				} else if (path->reserve_ap_adress) {
					path->nodes[path-> nnodes - 1 - i].flags |= RESERVE_AP;
				}
				break;
			}
		}
	}
}

static void __attribute__((unused))
printpath(const struct setup_path *path)
{
	int i;
	char c;
	printf("start %s -> ", path->sps[0].prev_ip);
	printf("%s ", path->sps[1].prev_ip);
	for (i = 0; i < path->nnodes - 1; i++) {
		c = (path->nodes[i].flags & X_NODE)? 'x' : 'y';
		putchar(c);
		if (path->nodes[i].flags & T_NODE) {
			putchar('t');
		}
		printf(" -> %s  ", path->sps[i].next_ip);
	}
	putchar('y');
	printf(" -> %s end ", path->sps[path->nnodes - 1].next_ip);
	printf("(%s)\n", (path->is_reverse_path)? "reverse" : "not reverse");
}

static int
generate_path_construction_keys(struct setup_path *path)
{
	BUF_MEM *bptr;
	BIO *bio;
	int ret;
	path->construction_certificate = RSA_generate_key(RSA_KEY_LEN, 65537, NULL, NULL);
	if (path->construction_certificate == NULL) {
		return -1;
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		return -1;
	}
	ret = PEM_write_bio_RSAPublicKey(bio, path->construction_certificate);
	if (ret == 0) {
		BIO_free(bio);
		return -1;
	}
	BIO_get_mem_ptr(bio, &bptr);
	assert(BIO_set_close(bio, BIO_NOCLOSE) == 1);
	BIO_free(bio);
	path->construction_certificate_len = bptr->length;
	path->construction_certificate_data = malloc(bptr->length);
	if (path->construction_certificate_data == NULL) {
		BUF_MEM_free(bptr);
		return -1;
	}
	memcpy(path->construction_certificate_data, bptr->data, bptr->length);
	BUF_MEM_free(bptr);
	return 0;
}

static void
generate_setup_packages(const struct config *config, struct setup_path *path, int nround)
{
	struct setup_package **sps;
	struct node_info **nodes;
	int i, nnodes;
	sps = alloca(path->nnodes * sizeof (struct setup_package *));
	nodes = alloca(path->nnodes * sizeof (struct node_info *));

	assert(nround == 1 || nround == 2);
	assert(path->nnodes > 1);
	assert(path->nxnodes > 1);
	if (nround == 1) {
		for (i = 0; i < path->nnodes; i++) {
			sps[i] = &(path->sps[i]);
			nodes[i] = &(path->nodes[i]);
		}
		nnodes = path->nnodes;
	} else {
		/* tell all nodes round 1 was successfull */
		/* and throw away the old contents of the nodes */
		/* but save old prev_id for correct symm encryption */
		for (i = 0; i < path->nnodes; i++) {
			memcpy(path->sps[i].old_prev_id, path->sps[i].prev_id, SHA_DIGEST_LENGTH);
			path->sps[i].flags |= SUCCESS_FLAG;
			free(path->contents[i]);
		}
		nnodes = 0;
		/* collect x nodes and packages */
		for (i = 0; i < path->nnodes; i++) {
			if (path->sps[i].flags & X_NODE) {
				sps[nnodes] = &(path->sps[i]);
				nodes[nnodes] = &(path->nodes[i]);
				nnodes++;
			}
		}
		assert(nnodes == path->nxnodes);
		/* now repack the x packages */
	}
	/* first node */
	sps[0]->prev_ip = config->ip;
	sps[0]->prev_port = config->port;
	sps[0]->next_ip = nodes[1]->ip;
	sps[0]->next_port = nodes[1]->port;
	rand_bytes(sps[0]->prev_id, SHA_DIGEST_LENGTH);
	rand_bytes(sps[0]->next_id, SHA_DIGEST_LENGTH);
	rand_bytes(sps[0]->replaceseed, SYMMETRIC_CIPHER_KEY_LEN);
	sps[0]->prev_communication_certificate_flat = config->communication_certificate_flat;
	sps[0]->next_communication_certificate_flat = nodes[1]->communication_certificate_flat;
	sps[0]->flags |= nodes[0]->flags;
	/* intermediary nodes */
	for (i = 1; i < nnodes - 1; i++) {
		sps[i]->prev_ip = nodes[i - 1]->ip;
		sps[i]->prev_port = nodes[i - 1]->port;
		sps[i]->next_ip = nodes[i + 1]->ip;
		sps[i]->next_port = nodes[i + 1]->port;
		rand_bytes(sps[i]->next_id, SHA_DIGEST_LENGTH);
		rand_bytes(sps[i]->replaceseed, SYMMETRIC_CIPHER_KEY_LEN);
		memcpy(sps[i]->prev_id, sps[i - 1]->next_id, SHA_DIGEST_LENGTH);
		sps[i]->prev_communication_certificate_flat = nodes[i - 1]->communication_certificate_flat;
		sps[i]->next_communication_certificate_flat = nodes[i + 1]->communication_certificate_flat;
		sps[i]->flags |= nodes[i]->flags;
	}

	/* last node */
	sps[nnodes - 1]->prev_ip = nodes[nnodes - 2]->ip;
	sps[nnodes - 1]->prev_port = nodes[nnodes - 2]->port;
	sps[nnodes - 1]->next_ip = config->ip;
	sps[nnodes - 1]->next_port = config->port;
	memcpy(sps[nnodes - 1]->prev_id, sps[nnodes - 2]->next_id, SHA_DIGEST_LENGTH);
	memcpy(sps[nnodes - 1]->next_id, sps[0]->prev_id, SHA_DIGEST_LENGTH);
	rand_bytes(sps[nnodes - 1]->replaceseed, SYMMETRIC_CIPHER_KEY_LEN);
	sps[nnodes - 1]->prev_communication_certificate_flat = nodes[nnodes - 2]->communication_certificate_flat;
	sps[nnodes - 1]->next_communication_certificate_flat = config->communication_certificate_flat;
	if (nround == 2) {
		for (i = 0; i < nnodes; i++) {
			sps[i]->nkeys = config->nkeys;
			rand_bytes(sps[i]->startkey, SYMMETRIC_CIPHER_KEY_LEN);
			rand_bytes(sps[i]->salt, SYMMETRIC_CIPHER_KEY_LEN);
			rand_bytes(sps[i]->replaceseed, SYMMETRIC_CIPHER_KEY_LEN);
		}
	}
}

static uint8_t *
encrypt_setup_package_asymmetric(const uint8_t *serialized, uint32_t len, EVP_PKEY *pubkey, int *outlen)
{
	int ret, tmp, privkeylen;
	uint32_t crypted;
	uint8_t *out, *p;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *type = EVP_aes_256_cbc();
	out = malloc((len / SYMMETRIC_CIPHER_BLOCK_SIZE) * SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_BLOCK_SIZE + EVP_PKEY_size(pubkey) + SYMMETRIC_CIPHER_IV_LEN + 2 * 4);
	if (out == NULL) {
		return NULL;
	}
	EVP_CIPHER_CTX_init(&ctx);
	p = out + SYMMETRIC_CIPHER_IV_LEN + 2 * 4;
	ret = EVP_SealInit(&ctx, type, &p, &privkeylen, out + 2 * 4, &pubkey, 1);
	assert (privkeylen == EVP_PKEY_size(pubkey));
	if (ret == 0) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		free(out);
		return NULL;
	}
	ret = EVP_SealUpdate(&ctx, out + EVP_PKEY_size(pubkey) + SYMMETRIC_CIPHER_IV_LEN + 2 * 4, &tmp, serialized, len);
	crypted = tmp;
	if (ret == 0) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		free(out);
		return NULL;
	}
	ret = EVP_SealFinal(&ctx, out + crypted + EVP_PKEY_size(pubkey) + SYMMETRIC_CIPHER_IV_LEN + 2 * 4, &tmp);
	crypted += tmp;
	if (ret == 0) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		free(out);
		return NULL;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);
	assert(crypted == (len / SYMMETRIC_CIPHER_BLOCK_SIZE) * SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_BLOCK_SIZE);
	serialize_32_t(crypted, out);
	serialize_32_t(EVP_PKEY_size(pubkey), out + 4);
	*outlen = crypted + EVP_PKEY_size(pubkey) + SYMMETRIC_CIPHER_IV_LEN + 2 * 4;
	return out;
}

static uint8_t *
encrypt_symmetric(const uint8_t *serialized, uint32_t len, const uint8_t *key, int *outlen)
{
	int ret, tmp;
	uint32_t crypted;
	uint8_t *out;
	EVP_CIPHER_CTX ctx;
	uint8_t sizedkey[SYMMETRIC_CIPHER_KEY_LEN];
	const EVP_CIPHER *type = EVP_aes_256_cbc();
	out = calloc((len / SYMMETRIC_CIPHER_BLOCK_SIZE) * SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_IV_LEN, 1);
	if (out == NULL) {
		return NULL;
	}
	pad_key(key, SHA_DIGEST_LENGTH, sizedkey, SYMMETRIC_CIPHER_KEY_LEN);
	rand_bytes(out, EVP_CIPHER_iv_length(type));
	EVP_CIPHER_CTX_init(&ctx);
	ret = EVP_EncryptInit(&ctx, type, sizedkey, out);
	if (ret == 0) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		free(out);
		return NULL;
	}
	ret = EVP_EncryptUpdate(&ctx, out + SYMMETRIC_CIPHER_IV_LEN, &tmp, serialized, len);
	crypted = tmp;
	if (ret == 0) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		free(out);
		return NULL;
	}
	ret = EVP_EncryptFinal(&ctx, out + crypted + SYMMETRIC_CIPHER_IV_LEN, &tmp);
	crypted += tmp;
	if (ret == 0) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		free(out);
		return NULL;
	}

	EVP_CIPHER_CTX_cleanup(&ctx);
	assert(crypted == (len / SYMMETRIC_CIPHER_BLOCK_SIZE) * SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_BLOCK_SIZE);
	*outlen = crypted + SYMMETRIC_CIPHER_IV_LEN;
	return out;
}

static int
sign_data(uint8_t *sig, const uint8_t *data, uint32_t len, EVP_PKEY *key)
{
	int ret;
	uint32_t written;
	EVP_MD_CTX ctx;
	const EVP_MD *type = EVP_sha1();
	EVP_MD_CTX_init(&ctx);
	EVP_SignInit(&ctx, type);
	ret = EVP_SignUpdate(&ctx, data, len);
	if (ret != 1) {
		return -1;
	}
	ret = EVP_SignFinal(&ctx, sig, &written, key);
	if (ret != 1) {
		return -1;
	}
	EVP_MD_CTX_cleanup(&ctx);
	assert(written == RSA_SIGN_LEN);
	return 0;
}

static int
check_signed_data(const uint8_t *sig, uint32_t siglen, const uint8_t *data, uint32_t len, EVP_PKEY *key)
{
	int ret;
	EVP_MD_CTX ctx;
	const EVP_MD *type = EVP_sha1();
	EVP_MD_CTX_init(&ctx);
	EVP_VerifyInit(&ctx, type);
	ret = EVP_VerifyUpdate(&ctx, data, len);
	if (ret != 1) {
		return -1;
	}
	ret = EVP_VerifyFinal(&ctx, sig, siglen, key);
	if (ret != 1) {
		return -1;
	}
	EVP_MD_CTX_cleanup(&ctx);
	return 0;
}

static DummySetupPackage *
create_dummy(struct dummy_package *dp)
{
	DummySetupPackage *d;
	d = malloc(sizeof (DummySetupPackage));
	if (d == NULL) {
		return NULL;
	}
	dummy_setup_package__init(d);
	/*ProtobufCBinaryData seed;*/
	/*fixed32 size;*/
	/*fixed32 flags;*/
	assert(SYMMETRIC_CIPHER_KEY_LEN >= SHA_DIGEST_LENGTH);
	d->seed.len = SYMMETRIC_CIPHER_KEY_LEN;
	d->seed.data = dp->seed;
	/* d->size will be set later on */
	/* d->flags will be set later on */
	return d;
}

static SetupPackage *
sps_to_SetupPackage(struct setup_path *path, int package_index, int nround)
{
	SetupPackage *sp;
	struct setup_package *ssp;
	uint32_t i;
	cleanup_stack_init;
	assert(nround == 1 || nround == 2);
	ssp = &path->sps[package_index];
	sp = calloc(1, sizeof (SetupPackage));
	if (sp == NULL) {
		return NULL;
	}
	cleanup_stack_push(free, sp);
	setup_package__init(sp);
	sp->dummies = calloc(ssp->ndummies, sizeof (DummySetupPackage *));
	if (sp->dummies == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	/*required string prev_ip = 1;*/
	/*required string next_ip = 2;*/
	/*required uint32 prev_port = 3;*/
	/*required uint32 next_port = 4;*/
	/*required bytes prev_id = 5;*/
	/*required bytes next_id = 6;*/
	/*required bytes prev_communication_certificate_flat = 7;*/
	/*required bytes next_communication_certificate_flat = 8;*/
	/*required bytes construction_certificate_flat = 9;*/
	/*repeated dummy_setup_package dummies = 10;*/
	/*required uint32 nkeys = 11;*/
	/*required bytes key_seed = 12;*/
	/*required bytes replacement_seed = 13;*/
	/*required bytes key_salt = 14;*/
	/*required uint32 flags = 15;*/
	/*required bytes hash = 16;*/
	/*required bytes external_hash = 17;*/
	/*optional string ap_adress = 18;*/
	/*optional bytes routing_table_entry = 19;*/
	sp->prev_ip = ssp->prev_ip;
	if ((ssp->flags & T_NODE) && (ssp->flags & X_NODE) && !  path->is_reverse_path && nround == 2) {
		static char emptystring[] = {'"', '"', '\0'};
		sp->next_ip = emptystring;  /*set next_ip to 0 */
	} else {
		sp->next_ip = ssp->next_ip;
	}
	sp->prev_port = ssp->prev_port;
	sp->next_port = ssp->next_port;
	sp->prev_id.len = SHA_DIGEST_LENGTH;
	sp->prev_id.data = ssp->prev_id;
	sp->next_id.len = SHA_DIGEST_LENGTH;
	if ((ssp->flags & T_NODE) && (ssp->flags & X_NODE) && !  path->is_reverse_path && nround == 2) {
		bzero(ssp->next_id, SHA_DIGEST_LENGTH); /* set next_id to all zero */
	}
	sp->next_id.data = ssp->next_id;
	sp->next_communication_certificate_flat.len = ssp->next_communication_certificate_flat->len;
	sp->next_communication_certificate_flat.data = ssp->next_communication_certificate_flat->data;
	sp->prev_communication_certificate_flat.len = ssp->prev_communication_certificate_flat->len;
	sp->prev_communication_certificate_flat.data = ssp->prev_communication_certificate_flat->data;
	sp->construction_certificate_flat.len = path->construction_certificate_len;
	sp->construction_certificate_flat.data = path->construction_certificate_data;
	sp->n_dummies = ssp->ndummies;
	for (i = 0; i < sp->n_dummies; i++) {
		sp->dummies[i] = create_dummy(&ssp->dummies[i]);
		if (sp->dummies[i] == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		cleanup_stack_push(free, sp->dummies[i]);
	}
	sp->nkeys = ssp->nkeys;
	sp->key_seed.len = SYMMETRIC_CIPHER_KEY_LEN;
	sp->key_seed.data = ssp->startkey;
	sp->replacement_seed.len = SYMMETRIC_CIPHER_KEY_LEN;
	sp->replacement_seed.data = ssp->replaceseed;
	sp->key_salt.len = SYMMETRIC_CIPHER_KEY_LEN;
	sp->key_salt.data = ssp->salt;
	sp->flags = ssp->flags;
	sp->hash.len = SHA_DIGEST_LENGTH;
	/* hash will be set later  */
	sp->external_hash.len = SHA_DIGEST_LENGTH;
	/* external_hash will be set later  */
	if ((ssp->flags & T_NODE) && path->entrypath && nround == 2) {
		int ret;
		/* add routing table entry and own ap adress */
		assert(sizeof (path->ap.s6_addr) == 16);
		sp->has_ap_adress = 1;
		sp->ap_adress.data = path->ap.s6_addr;
		sp->ap_adress.len = 16;
		ret = add_routing_table_entry(sp, &path->ap, &path->entry_ip, 1);
		if (ret != 0) {
			cleanup_stack_free_all();
			return NULL;
		}
	}
	/* no free all, since we want to keep all our allocs in case of success */
	return sp;
}

static void
setup_package_free(SetupPackage *s)
{
	uint32_t i;
	if (s->dummies != NULL) {
		for (i = 0; i < s->n_dummies; i++) {
			if (s->dummies[i] != NULL) {
				free(s->dummies[i]);
			}
		}
		free(s->dummies);
	}
	if (s->hash.data != NULL) {
		free(s->hash.data);
	}
	if (s->external_hash.data != NULL) {
		free(s->external_hash.data);
	}
	if (s->rte != NULL) {
		if (s->rte->ip_adresses != NULL) {
			free(s->rte->ip_adresses);
		}
		if (s->rte->ports != NULL) {
			free(s->rte->ports);
		}
		free(s->rte);
	}
	free(s);
}

static int
calculate_expected_size(uint32_t size, EVP_PKEY *pubkey)
{
	return (((size / SYMMETRIC_CIPHER_BLOCK_SIZE) *
		 SYMMETRIC_CIPHER_BLOCK_SIZE + EVP_PKEY_size(pubkey) +
		 SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_IV_LEN + 2 * 4) /
		SYMMETRIC_CIPHER_BLOCK_SIZE) * SYMMETRIC_CIPHER_BLOCK_SIZE +
		SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_IV_LEN +
		RSA_SIGN_LEN;
}

struct tracking_info {
	int nentries;
	uint8_t endhash[SHA_DIGEST_LENGTH];
	struct tracking_entry *entries;
};

struct tracking_entry {
	struct tracking_entry *next;
	struct tracking_entry *prev;
	uint8_t hash[SHA_DIGEST_LENGTH];
};

static void
free_tracking_info(struct tracking_info *t)
{
	if (t->entries != NULL) {
		free(t->entries);
	}
	free(t);
}

static struct tracking_info *
new_tracking_info(int nnodes)
{
	struct tracking_info *t = calloc(1, sizeof (struct tracking_info));
	if (t == NULL) {
		return NULL;
	}
	t->nentries = nnodes;
	t->entries = calloc(nnodes, sizeof (struct tracking_entry));
	if (t->entries == NULL) {
		free(t);
		return NULL;
	}
	return t;
}


static uint8_t *
generate_dummy_payload(uint8_t *seed, int size)
{
	uint8_t *buf;
	struct rc4_rand *r;
	buf = malloc(size);
	if (buf == NULL) {
		return NULL;
	}
	r = rc4_rand_init(seed, SYMMETRIC_CIPHER_KEY_LEN);
	if (r == NULL) {
		free(buf);
		return NULL;
	}
	rc4_rand_bytes(r, buf, size);
	rc4_rand_free(r);
	return buf;
}

/*create and destroy dummy packages keep track of their hashes + which one are valid for which node */
static struct tracking_info *
create_dummy_package_information(SetupPackage **sps, int nnodes)
{
	struct tracking_info *t;
	struct tracking_entry *help1, *help2, *tmp, curlist, addlist;
	int i, cur_dummies, add, delete;
	uint32_t j;
	uint8_t *generated;
	LIST_init(&curlist);
	LIST_init(&addlist);
	t = new_tracking_info(nnodes);
	if (t == NULL) {
		return NULL;
	}
	cur_dummies = 0;
	for (i = 0; i < nnodes; i++) {
		bzero(t->entries[i].hash, SHA_DIGEST_LENGTH);
		LIST_for_all(&curlist, help1, help2){
			xor(t->entries[i].hash, help1->hash, SHA_DIGEST_LENGTH);
		}
		for (j = 0; j < sps[i]->n_dummies; j++) {
			if (LIST_is_empty(&curlist)) {
				add = 1;
			} else {
				add = rand_range(0, 2);
			}
			if (add) {
				generated = generate_dummy_payload(sps[i]->dummies[j]->seed.data, sps[i]->dummies[j]->size);
				if (generated == NULL) {
					LIST_clear(&addlist, help1);
					LIST_clear(&curlist, help1);
					free_tracking_info(t);
					return NULL;
				}
				tmp = calloc(1, sizeof (struct tracking_entry));
				if (tmp == NULL) {
					free(generated);
					LIST_clear(&addlist, help1);
					LIST_clear(&curlist, help1);
					free_tracking_info(t);
					return NULL;
				}
				sps[i]->dummies[j]->flags = DUMMY_INSERT;
				SHA1(generated, sps[i]->dummies[j]->size, tmp->hash);
				free(generated);
				LIST_insert(&addlist, tmp);
			} else {
				assert(cur_dummies);
				delete = rand_range(0, cur_dummies);
				LIST_for_all(&curlist, help1, help2) {
					if (!delete) {
						break;
					}
					delete--;
				}
				assert(sps[i]->dummies[j]->seed.len <= SYMMETRIC_CIPHER_KEY_LEN);
				memcpy(sps[i]->dummies[j]->seed.data, help1->hash, SHA_DIGEST_LENGTH);
				sps[i]->dummies[j]->flags = DUMMY_DELETE;
				LIST_remove(help1);
				free(help1);
				cur_dummies--;
			}
		}
		LIST_for_all(&addlist, help1, help2) {
			LIST_remove(help1);
			LIST_insert(&curlist, help1);
			cur_dummies++;
		}
		assert(LIST_is_empty(&addlist));
		assert(cur_dummies >= 0);
	}
	assert(LIST_is_empty(&addlist));
	LIST_for_all(&curlist, help1, help2){
		xor(t->endhash, help1->hash, SHA_DIGEST_LENGTH);
	}
	LIST_clear(&curlist, help1);
	return t;
}

static void
add_external_hash(SetupPackage *sp, const uint8_t *replaced_hashes, const uint8_t *original_hashes, int idx, const struct tracking_info *tracking, int nnodes)
{
	int i;
	bzero(sp->external_hash.data, SHA_DIGEST_LENGTH);
	for (i = nnodes - 1; i > idx; i--) {
		xor(sp->external_hash.data, original_hashes + i * SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
	}
	for (i = 0; i < idx; i++) {
		xor(sp->external_hash.data, replaced_hashes + i * SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
	}
	xor(sp->external_hash.data, tracking->entries[idx].hash, SHA_DIGEST_LENGTH);
}

static uint8_t *
generate_replaced_hashes(SetupPackage **sps, const uint32_t *sizes, int nnodes)
{
	int i;
	uint8_t *h, *generated;
	h = malloc(nnodes * SHA_DIGEST_LENGTH);
	if (h == NULL) {
		return NULL;
	}
	for (i = 0; i < nnodes ; i++) {
		generated = generate_dummy_payload(sps[i]->replacement_seed.data, sizes[i]);
		if (generated == NULL) {
			free(h);
			return NULL;
		}
		SHA1(generated, sizes[i], h + i * SHA_DIGEST_LENGTH);
		free(generated);
	}
	return h;
}

static uint8_t *
pack_setup_array(const uint8_t *id, uint8_t **slots, const uint32_t *sizes, int num_slots, uint32_t *outsize, int randomize)
{
	uint32_t *mixed_sizes, size_tmp, ret, total;
	uint8_t **mixed_slots, *slot_tmp, *out;
	int i, pos;
	SetupArray a = SETUP_ARRAY__INIT;
	cleanup_stack_init;
	mixed_sizes = malloc(num_slots * sizeof (uint32_t));
	if (mixed_sizes == NULL) {
		return NULL;
	}
	cleanup_stack_push(free, mixed_sizes);
	mixed_slots = malloc(num_slots * sizeof (uint8_t *));
	if (mixed_slots== NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, mixed_slots);
	memcpy(mixed_slots, slots, num_slots * sizeof(uint8_t *));
	memcpy(mixed_sizes, sizes, num_slots * sizeof(uint32_t));
	if (randomize) {
		for (i = 0; i < num_slots; i++) {
			pos = rand_range(0, num_slots);
			if (pos == i) {
				continue;
			}
			size_tmp = mixed_sizes[i];
			slot_tmp = mixed_slots[i];
			mixed_sizes[i] = mixed_sizes[pos];
			mixed_slots[i] = mixed_slots[pos];
			mixed_sizes[pos] = size_tmp;
			mixed_slots[pos] = slot_tmp;
		}
	}
	a.n_slots = num_slots;
	a.slots = malloc (num_slots * sizeof (ProtobufCBinaryData));
	if (a.slots == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, a.slots);
	for (i = 0; i < num_slots; i++) {
		a.slots[i].len = mixed_sizes[i];
		a.slots[i].data = mixed_slots[i];
	}
	total = setup_array__get_packed_size(&a);
	out = malloc(total + SHA_DIGEST_LENGTH);
	if (out == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = setup_array__pack(&a, out + SHA_DIGEST_LENGTH);
	assert(ret == total);
	memcpy(out, id, SHA_DIGEST_LENGTH);
	*outsize = total + SHA_DIGEST_LENGTH;
	cleanup_stack_free_all();
	return out;
}

static uint8_t *
create_setup_array(struct setup_path *path, SetupPackage **sps, const uint32_t *expected_sizes, uint32_t *sizes, const struct tracking_info *tracking_info, uint32_t *outsize, int nround)
{
	EVP_PKEY *privkey;
	uint8_t *replaced_hashes, *original_hashes, **packed, *out;
	int ret, i;
	cleanup_stack_init;
	privkey = EVP_PKEY_new();
	if (privkey == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(EVP_PKEY_free, privkey);
	ret = EVP_PKEY_set1_RSA(privkey, path->construction_certificate);
	if (ret != 1) {
		cleanup_stack_free_all();
		return NULL;
	}
	packed = malloc(path->nnodes * sizeof(uint8_t *));
	if (packed == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, packed);
	replaced_hashes = generate_replaced_hashes(sps, expected_sizes, path->nnodes);
	if (replaced_hashes == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, replaced_hashes);
	original_hashes = malloc(path->nnodes * SHA_DIGEST_LENGTH);
	if (original_hashes == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, original_hashes);
	/* add external hashes to package, pack it and encrypt asymmetrically
	 * with receiving nodes public key
	 * loop is reverse */
	for (i = path->nnodes - 1; i >= 0; i--) {
		EVP_PKEY *pubkey;
		int outlen;
		uint8_t sig[RSA_SIGN_LEN], *oldcontents;
		pubkey = X509_get_pubkey(path->nodes[i].construction_certificate);
		if (pubkey == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		add_external_hash(sps[i], replaced_hashes, original_hashes, i, tracking_info, path->nnodes);
		packed[i] = calloc(1, sizes[i]);
		if (packed[i] == NULL) {
			EVP_PKEY_free(pubkey);
			cleanup_stack_free_all();
			return NULL;
		}
		cleanup_stack_push(free, packed[i]);
		bzero(sps[i]->hash.data, SHA_DIGEST_LENGTH);
		ret = setup_package__pack(sps[i], packed[i]);
		if (ret == 0) {
			cleanup_stack_free_all();
			EVP_PKEY_free(pubkey);
			return NULL;
		}
		SHA1(packed[i], sizes[i], sps[i]->hash.data);
		ret = setup_package__pack(sps[i], packed[i]);
		if (ret == 0) {
			EVP_PKEY_free(pubkey);
			cleanup_stack_free_all();
			return NULL;
		}
		/* encrypt asymmetrically (iv and symm key are prepended) */
		path->contents[i] = encrypt_setup_package_asymmetric(packed[i], sizes[i], pubkey, &outlen);
		sizes[i] = outlen;
		EVP_PKEY_free(pubkey);
		if (path->contents[i] == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		cleanup_stack_push(free, path->contents[i]);
		if (nround == 1) {
			path->contents[i] = encrypt_symmetric(path->contents[i], sizes[i], path->sps[i].prev_id, &outlen);
		} else {
			path->contents[i] = encrypt_symmetric(path->contents[i], sizes[i], path->sps[i].old_prev_id, &outlen);
		}
		if (path->contents[i] == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		sizes[i] = outlen;
		ret = sign_data(sig, path->contents[i], sizes[i], privkey);
		if (ret != 0) {
			cleanup_stack_free_all();
			return NULL;
		}
		sizes[i] += RSA_SIGN_LEN;
		assert(expected_sizes[i] == sizes[i]);
		oldcontents = path->contents[i];
		path->contents[i] = malloc(sizes[i]);
		if (path->contents[i] == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		/* prepend signature */
		memcpy(path->contents[i], sig, RSA_SIGN_LEN);
		memcpy(path->contents[i] + RSA_SIGN_LEN, oldcontents, sizes[i] - RSA_SIGN_LEN);
		free(oldcontents);
		SHA1(path->contents[i], sizes[i], original_hashes + i * SHA_DIGEST_LENGTH);
	}
	bzero(path->endhash, SHA_DIGEST_LENGTH);
	memcpy(path->endhash, tracking_info->endhash, SHA_DIGEST_LENGTH);
	for (i = 0; i < path->nnodes; i++) {
		xor(path->endhash, replaced_hashes + i * SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
	}
	if (nround == 1) {
		out = pack_setup_array(path->sps[0].prev_id, path->contents, sizes, path->nnodes, outsize, 1);
	} else {
		out = pack_setup_array(path->sps[0].old_prev_id, path->contents, sizes, path->nnodes, outsize, 1);
	}
	cleanup_stack_free_all();
	return out;
}

static uint8_t *
pack_setup_packages(struct setup_path *path, uint32_t *outsize, int nround)
{
	int i;
	SetupPackage **sps;
	uint32_t *sizes, *expected_sizes;
	uint8_t *out;
	struct tracking_info *tracking;
	EVP_PKEY *pubkey;
	cleanup_stack_init;
	assert(nround == 1 || nround == 2);
	sps = malloc(path->nnodes * sizeof (SetupPackage *));
	if (sps == NULL) {
		return NULL;
	}
	cleanup_stack_push(free, sps);
	sizes = malloc(path->nnodes * sizeof (uint32_t));
	if (sizes == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, sizes);
	expected_sizes = malloc(path->nnodes * sizeof (uint32_t));
	if (expected_sizes == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, expected_sizes);
	for (i = 0; i < path->nnodes; i++) {
		pubkey = X509_get_pubkey(path->nodes[i].construction_certificate);
		if (pubkey == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		sps[i] = sps_to_SetupPackage(path, i, nround);
		if (sps[i] == NULL) {
			EVP_PKEY_free(pubkey);
			cleanup_stack_free_all();
			return NULL;
		}
		cleanup_stack_push(setup_package_free, sps[i]);
		sizes[i] = setup_package__get_packed_size(sps[i]);
		expected_sizes[i] = calculate_expected_size(sizes[i], pubkey);
		EVP_PKEY_free(pubkey);
	}
	for (i = 0; i < path->nnodes; i++) {
		uint32_t j;
		for (j = 0; j < sps[i]->n_dummies; j++) {
			sps[i]->dummies[j]->size = expected_sizes[rand_range(0, path->nnodes)];
		}
		assert(sps[i]->hash.data == NULL);
		sps[i]->hash.data = malloc(SHA_DIGEST_LENGTH);
		if (sps[i]->hash.data == NULL) {
			cleanup_stack_free_all();
			return NULL;
		} /* do notfree hashes -> sps_delete will do it */
		assert(sps[i]->external_hash.data == NULL);
		sps[i]->external_hash.data = malloc(SHA_DIGEST_LENGTH);
		if (sps[i]->external_hash.data == NULL) {
			cleanup_stack_free_all();
			return NULL;
		} /* do not free external_hashes -> sps_delete will do it */
	}
	tracking = create_dummy_package_information(sps, path->nnodes);
	if (tracking == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free_tracking_info, tracking);
	out = create_setup_array(path, sps, expected_sizes, sizes, tracking, outsize, nround);
	cleanup_stack_free_all();
	return out;
}

static int
decide_about_participation(uint32_t flags)
{
	(void) flags;
	return 0;
}

static void
sa_array_cleanup_helper(SetupArray *a)
{
	setup_array__free_unpacked(a, NULL);
}

static void
setup_package_cleanup_helper(SetupPackage *s)
{
	setup_package__free_unpacked(s, NULL);
}

static int
validate_routing_table_entry(RoutingTableEntry *r)
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

static int
validate_sp(const SetupPackage *sp)
{
	uint32_t i;
	if (sp->prev_id.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	if (sp->next_id.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	if (sp->key_seed.len != SYMMETRIC_CIPHER_KEY_LEN) {
		return -1;
	}
	if (sp->key_salt.len != SYMMETRIC_CIPHER_KEY_LEN) {
		return -1;
	}
	if (sp->replacement_seed.len != SYMMETRIC_CIPHER_KEY_LEN) {
		return -1;
	}
	if (sp->hash.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	if (sp->external_hash.len != SHA_DIGEST_LENGTH) {
		return -1;
	}
	if (sp->prev_port>>16) {
		return -1;
	}
	if (sp->next_port>>16) {
		return -1;
	}
	if (sp->prev_communication_certificate_flat.len < 4) {
		return -1;
	}
	if (sp->next_communication_certificate_flat.len < 4) {
		return -1;
	}
	if (sp->construction_certificate_flat.len < 4) {
		return -1;
	}
	for (i = 0; i < sp->n_dummies; i++) {
		if (!(sp->dummies[i]->flags & (DUMMY_INSERT | DUMMY_DELETE))) {
			return -1;
		}
		if (sp->dummies[i]->flags & DUMMY_INSERT && sp->dummies[i]->flags & DUMMY_DELETE) {
			return -1;
		}
		if (sp->dummies[i]->seed.len != SYMMETRIC_CIPHER_KEY_LEN) {
			return -1;
		}
	}
	if (sp->flags & SUCCESS_FLAG && sp->flags & X_NODE) {
		if (!sp->nkeys) {
			return -1;
		}
		if (sp->key_seed.len != SYMMETRIC_CIPHER_KEY_LEN) {
			return -1;
		}
		if (sp->key_salt.len != SYMMETRIC_CIPHER_KEY_LEN) {
			return -1;
		}
		if (sp->flags & ENTRY_NODE) {
			if (sp->ap_adress.len != 16) {
				return -1;
			}
			if (sp->rte == NULL) {
				return -1;
			}
			if (validate_routing_table_entry(sp->rte) != 0) {
				return -1;
			}
		}
	}
	return 0;
}

static int
extract_rte_information(const RoutingTableEntry *r, struct conn_ctx *conn)
{
	uint32_t ret;
	conn->rte.len = routing_table_entry__get_packed_size(r);
	conn->rte.data = malloc(conn->rte.len);
	if (conn->rte.data == NULL) {
		return -1;
	}
	ret = routing_table_entry__pack(r, conn->rte.data);
	if (ret != conn->rte.len) {
		return -1;
	}
	return 0;
}

static int
extract_slot_information(const SetupPackage *sp, struct conn_ctx *conn, int nround)
{
	/* all allocs will be freed by conn_ctx_free in case of failure */
	struct X509_flat x;
	BIO *mem;
	BUF_MEM bptr;
	assert(nround == 1 || nround == 2);
	memcpy(conn->prev_id, sp->prev_id.data, SHA_DIGEST_LENGTH);
	memcpy(conn->next_id, sp->next_id.data, SHA_DIGEST_LENGTH);
	conn->prev_ip = strdup(sp->prev_ip);
	if (conn->prev_ip == NULL) {
		return -1;
	}
	conn->next_ip = strdup(sp->next_ip);
	if (conn->next_ip == NULL) {
		return -1;
	}
	conn->prev_port = sp->prev_port;
	conn->next_port = sp->next_port;
	conn->flags = sp->flags;
	x.len = sp->prev_communication_certificate_flat.len;
	x.data = sp->prev_communication_certificate_flat.data;
	conn->prev_communication_certificate = read_x509_from_x509_flat(&x);
	x.len = sp->next_communication_certificate_flat.len;
	x.data = sp->next_communication_certificate_flat.data;
	conn->next_communication_certificate = read_x509_from_x509_flat(&x);
	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		return -1;
	}
	bptr.data = (char *) sp->construction_certificate_flat.data;
	bptr.length = sp->construction_certificate_flat.len;
	BIO_set_mem_buf(mem, &bptr, BIO_NOCLOSE);
	conn->construction_certificate = PEM_read_bio_RSAPublicKey(mem, NULL, NULL, NULL);
	BIO_free(mem);
	if (conn->construction_certificate == NULL) {
		return -1;
	}
	if (nround == 2 && sp->flags & X_NODE) {
		conn->keys = generate_conn_keys(sp->nkeys, sp->key_seed.data, sp->key_salt.data);
		if (conn->keys == NULL) {
			return -1;
		}
		if (sp->flags & T_NODE) {
			if (sp->flags & X_NODE && sp->flags & ENTRY_NODE) {
				assert(sp->ap_adress.len == 16);
				memcpy(conn->ap.s6_addr, sp->ap_adress.data, 16);
				if (extract_rte_information(sp->rte, conn) != 0) {
					return -1;
				}
			}
		}
	}
	return 0;
}

static int
validate_setup_array(const SetupArray *a)
{
	uint32_t i;
	if (a->n_slots < 1) {
		return -1;
	}
	for (i = 0; i < a->n_slots; i++) {
		if (a->slots[i].len < RSA_SIGN_LEN + SYMMETRIC_CIPHER_IV_LEN + 8) {
			return -1;
		}
	}
	return 0;
}

static int
check_external_hash(const SetupArray *a, const uint8_t *external_hash, uint32_t own_idx)
{
	uint32_t i;
	uint8_t hash[SHA_DIGEST_LENGTH], result[SHA_DIGEST_LENGTH];
	bzero(result, SHA_DIGEST_LENGTH);
	for (i = 0; i < a->n_slots; i++) {
		if (i == own_idx)  {
			continue;
		}
		SHA1(a->slots[i].data, a->slots[i].len, hash);
		xor(result, hash, SHA_DIGEST_LENGTH);
	}
	return memcmp(result, external_hash, SHA_DIGEST_LENGTH);
}

static int
contains_hash_of(const uint8_t *hashes, const uint8_t *data, int len, int nhashes)
{
	int i;
	uint8_t hash[SHA_DIGEST_LENGTH];
	SHA1(data, len, hash);
	for (i = 0; i < nhashes; i++) {
		if (!memcmp(hashes + i * SHA_DIGEST_LENGTH, hash, SHA_DIGEST_LENGTH)) {
			return 1;
		}
	}
	return 0;
}

static uint8_t *
modify_setup_array(const SetupArray *a, const SetupPackage *sp, const uint8_t *id, uint32_t own_idx, uint32_t *outsize)
{
	uint8_t *new, **slots, *delete_hashes;
	uint32_t nslots, *sizes, i, adds, deletes, cnt;
	cleanup_stack_init;
	nslots = a->n_slots;
	deletes = 0;
	adds = 0;
	for  (i = 0; i < sp->n_dummies; i++) {
		if (sp->dummies[i]->flags & DUMMY_INSERT) {
			nslots++;
			adds++;
		} else {
			nslots--;
			deletes++;
		}
	}
	slots = malloc(nslots * sizeof (uint8_t *));
	if (slots == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, slots);
	sizes = malloc(nslots * sizeof (uint32_t));
	if (sizes == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(free, sizes);
	delete_hashes = NULL;
	if (deletes) {
		delete_hashes = malloc(deletes * SHA_DIGEST_LENGTH);
		if (delete_hashes == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		cnt = 0;
		cleanup_stack_push(free, delete_hashes);
		for (i = 0; i < sp->n_dummies; i++) {
			if (sp->dummies[i]->flags & DUMMY_DELETE) {
				memcpy(delete_hashes + cnt * SHA_DIGEST_LENGTH, sp->dummies[i]->seed.data, SHA_DIGEST_LENGTH);
				cnt++;
			}
		}
	}
	cnt = 0;
	for (i = 0; i < a->n_slots; i++) {
		if (own_idx == i) {
			slots[cnt] = generate_dummy_payload(sp->replacement_seed.data, a->slots[own_idx].len);
			if (slots[cnt] == NULL) {
				cleanup_stack_free_all();
				return NULL;
			}
			cleanup_stack_push(free, slots[cnt]);
			sizes[cnt] = a->slots[own_idx].len;
			cnt++;
		} else if (delete_hashes && contains_hash_of(delete_hashes, a->slots[i].data, a->slots[i].len, deletes)) {
			continue;
		} else {
			slots[cnt] = a->slots[i].data;
			sizes[cnt] = a->slots[i].len;
			cnt++;
		}
	}
	for (i = 0; i < sp->n_dummies; i++) {
		if (sp->dummies[i]->flags & DUMMY_INSERT) {
			slots[cnt] = generate_dummy_payload(sp->dummies[i]->seed.data, sp->dummies[i]->size);
			if (slots[cnt] == NULL) {
				cleanup_stack_free_all();
				return NULL;
			}
			cleanup_stack_push(free, slots[cnt]);
			sizes[cnt] = sp->dummies[i]->size;
			cnt++;
		}
	}
	assert(cnt == nslots);
	new = pack_setup_array(id, slots, sizes, nslots, outsize, 1);
	cleanup_stack_free_all();
	return new;
}

static SetupArray *
extract_setup_array(const uint8_t *sa, int sa_len, const uint8_t *id, const struct config *config, int *own_slot, SetupPackage **own_sp)
{
	SetupArray *a;
	int outlen, written1, written2, ret, own_idx;
	uint32_t i, package_size, pubkey_size;
	uint8_t *out, hash[SHA_DIGEST_LENGTH], *oldout, received_hash[SHA_DIGEST_LENGTH], sizedkey[SYMMETRIC_CIPHER_KEY_LEN];
	SetupPackage *sp;
	EVP_CIPHER_CTX ctx;
	cleanup_stack_init;
	pad_key(id, SHA_DIGEST_LENGTH, sizedkey, SYMMETRIC_CIPHER_KEY_LEN);
	a = setup_array__unpack(NULL, sa_len, sa);
	if (a == NULL) {
		return NULL;
	}
	cleanup_stack_push(sa_array_cleanup_helper, a);
	ret = validate_setup_array(a);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	sp = NULL;
	own_idx = -1;
	for (i = 0; i < a->n_slots; i++) {
		package_size = a->slots[i].len - RSA_SIGN_LEN - SYMMETRIC_CIPHER_IV_LEN;
		if (package_size % SYMMETRIC_CIPHER_BLOCK_SIZE || package_size - (int32_t) package_size) {
			cleanup_stack_free_all();
			return NULL;
		}
		out = malloc(package_size);
		if (out == NULL) {
			cleanup_stack_free_all();
			return NULL;
		}
		cleanup_stack_push(free, out);
		EVP_CIPHER_CTX_init(&ctx);
		ret = EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), sizedkey, a->slots[i].data + RSA_SIGN_LEN);
		if (ret != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			cleanup_stack_free_all();
			return NULL;
		}
		ret = EVP_DecryptUpdate(&ctx, out, &written1, a->slots[i].data + RSA_SIGN_LEN + SYMMETRIC_CIPHER_IV_LEN, package_size);
		if (ret != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			cleanup_stack_free_all();
			return NULL;
		}
		ret = EVP_DecryptFinal(&ctx, out + written1, &written2);
		EVP_CIPHER_CTX_cleanup(&ctx);
		if (ret != 1) {
			/* wrong package - padding mismatch */
			cleanup_stack_pop(); /* out */
			continue;
		}
		outlen = written1 + written2;
		assert((outlen / SYMMETRIC_CIPHER_BLOCK_SIZE * SYMMETRIC_CIPHER_BLOCK_SIZE) + SYMMETRIC_CIPHER_BLOCK_SIZE == (int32_t) package_size);
		if (outlen < SYMMETRIC_CIPHER_IV_LEN + SYMMETRIC_CIPHER_KEY_LEN) {
			cleanup_stack_free_all();
			return NULL;
		}
		EVP_CIPHER_CTX_init(&ctx); /* reinit cipher for asymmetric decryption */
		if (ret != 1) {
			cleanup_stack_free_all();
			return NULL;
		}
		pubkey_size = deserialize_32_t(out + 4);
		ret = EVP_OpenInit(&ctx, EVP_aes_256_cbc(), out + 2 * 4 + SYMMETRIC_CIPHER_IV_LEN, pubkey_size, out + 2 * 4, config->private_construction_key);
		if (ret != 1) {
			/* wrong package - key not revoverable */
			/* bug in openssl doc - it is not the number of
			 * keybytes recovered returned if successful but
			 * constant 1 */
			EVP_CIPHER_CTX_cleanup(&ctx);
			cleanup_stack_pop(); /* out */
			continue;
		}
		oldout = out;
		out = malloc((package_size / SYMMETRIC_CIPHER_BLOCK_SIZE) * SYMMETRIC_CIPHER_BLOCK_SIZE + SYMMETRIC_CIPHER_BLOCK_SIZE);
		if (out == NULL) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			cleanup_stack_free_all();
			return NULL;
		}
		ret = EVP_OpenUpdate(&ctx, out, &written1, oldout + 2 * 4 + SYMMETRIC_CIPHER_IV_LEN + pubkey_size, deserialize_32_t(oldout));
		cleanup_stack_pop(); /* old_out */
		cleanup_stack_push(free, out);
		if (ret != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			cleanup_stack_free_all();
			return NULL;
		}
		ret = EVP_OpenFinal(&ctx, out + written1, &written2);
		EVP_CIPHER_CTX_cleanup(&ctx);
		if (ret != 1) {
			cleanup_stack_pop(); /* out */
			continue; /* wrong package */
		}
		outlen = written1 + written2;
		/* candidate for the right package - try to unpack it and check the hash */
		sp = setup_package__unpack(NULL, outlen, out);
		if (sp == NULL) {
			cleanup_stack_pop(); /* out */
			continue; /* wrong package */
		}
		ret = validate_sp(sp);
		if (ret != 0) {
			setup_package_cleanup_helper(sp);
			cleanup_stack_free_all();
			return NULL;
		}
		memcpy(received_hash, sp->hash.data, SHA_DIGEST_LENGTH);
		bzero(out, outlen);
		bzero(sp->hash.data, SHA_DIGEST_LENGTH);
		assert(setup_package__get_packed_size(sp) == (uint32_t) outlen);
		setup_package__pack(sp, out);
		SHA1(out, outlen, hash);
		if (memcmp(hash, received_hash, SHA_DIGEST_LENGTH)) {
			setup_package_cleanup_helper(sp);
			cleanup_stack_pop(); /* out */
			continue; /* wrong package */
		}
		memcpy(sp->hash.data, received_hash, SHA_DIGEST_LENGTH);
		cleanup_stack_pop(); /* out */
		own_idx = i;
		break;
	}
	if (own_idx == -1) {
		cleanup_stack_free_all();
		return NULL;
	}
	*own_slot = own_idx;
	*own_sp = sp;
	cleanup_stack_save_bottom(1); /* save array */
	return a;
}

uint8_t *
handle_first_round_setup_array(const struct config *config, const uint8_t *sa, int sa_len, const uint8_t *id, const char *from_ip, struct conn_ctx *conn, uint32_t *outsize)
{
	SetupArray *a;
	SetupPackage *sp;
	int own_idx, ret;
	uint8_t *new;
	cleanup_stack_init;
	a = extract_setup_array(sa, sa_len, id, config, &own_idx, &sp);
	if (a == NULL) {
		return NULL;
	}
	cleanup_stack_push(setup_package_cleanup_helper, sp);
	cleanup_stack_push(sa_array_cleanup_helper, a);
	if (memcmp(sp->prev_id.data, id, SHA_DIGEST_LENGTH)) {
		cleanup_stack_free_all();
		return NULL;
	}
	if (strcmp(from_ip, sp->prev_ip)) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = check_external_hash(a, sp->external_hash.data, own_idx);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = extract_slot_information(sp, conn, 1);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = decide_about_participation(conn->flags);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	new = modify_setup_array(a, sp, sp->next_id.data, own_idx, outsize);
	cleanup_stack_free_all();
	return new;
}

uint8_t *
handle_second_round_setup_array(const struct config *config, const uint8_t *sa, int sa_len, const uint8_t *id, const struct conn_ctx *oldconn, struct conn_ctx *conn, uint32_t *outsize)
{
	SetupArray *a;
	SetupPackage *sp;
	int own_idx, ret;
	uint8_t *new;
	EVP_PKEY *key;
	cleanup_stack_init;
	if (memcmp(oldconn->prev_id, id, SHA_DIGEST_LENGTH)) {
		return NULL;
	}
	a = extract_setup_array(sa, sa_len, id, config, &own_idx, &sp);
	if (a == NULL) {
		return NULL;
	}
	cleanup_stack_push(setup_package_cleanup_helper, sp);
	cleanup_stack_push(sa_array_cleanup_helper, a);
	ret = check_external_hash(a, sp->external_hash.data, own_idx);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	key = EVP_PKEY_new();
	if (key == NULL) {
		cleanup_stack_free_all();
		return NULL;
	}
	cleanup_stack_push(EVP_PKEY_free, key);
	ret = EVP_PKEY_set1_RSA(key, oldconn->construction_certificate);
	if (ret == 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = check_signed_data(a->slots[own_idx].data, RSA_SIGN_LEN, a->slots[own_idx].data + RSA_SIGN_LEN, a->slots[own_idx].len - RSA_SIGN_LEN, key);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	if (! (conn->flags | SUCCESS_FLAG)) {
		cleanup_stack_free_all();
		return NULL;
	}
	ret = extract_slot_information(sp, conn, 2);
	if (ret != 0) {
		cleanup_stack_free_all();
		return NULL;
	}
	new = modify_setup_array(a, sp, oldconn->next_id, own_idx, outsize);
	cleanup_stack_free_all();
	return new;
}

static int
send_x_package(struct setup_path *path, const struct config *config)
{
	int ret, x_idx;
	uint8_t preface[4];
	/* find first x_node */
	for (x_idx = 0; x_idx < path->nnodes; x_idx++) {
		if (path->sps[x_idx].flags & X_NODE) {
			break;
		}
	}
	free_ssl_connection(path->ssl_conn);
	path->ssl_conn = create_ssl_connection(path->nodes[x_idx].ip, path->nodes[x_idx].port, config->communication_certificate, config->private_communication_key);
	if (path->ssl_conn == NULL) {
		return -1;
	}
	if (! X509_compare(path->ssl_conn->peer_cert, path->nodes[x_idx].communication_certificate)) {
		return -1;
	}
	serialize_32_t(SHA_DIGEST_LENGTH, preface);
	ret = ssl_write(path->ssl_conn->ssl, preface, 4);
	if (ret != 0) {
		return -1;
	}
	ret = ssl_write(path->ssl_conn->ssl, path->sps[x_idx].prev_id, SHA_DIGEST_LENGTH);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

static int
send_setup_array(struct setup_path *path, const struct config *config, const uint8_t *array, uint32_t array_len, int nround)
{
	int ret;
	uint8_t preface[4];
	assert(nround == 1 || nround == 2);
	serialize_32_t(array_len, preface);
	if (nround == 1) {
		path->ssl_conn = create_ssl_connection(path->nodes[0].ip, path->nodes[0].port, config->communication_certificate, config->private_communication_key);
		if (path->ssl_conn == NULL) {
			return -1;
		}
		if (! X509_compare(path->ssl_conn->peer_cert, path->nodes[0].communication_certificate)) {
			return -1;
		}
	}
	ret = ssl_write(path->ssl_conn->ssl, preface, 4);
	if (ret != 0) {
		return -1;
	}
	ret = ssl_write(path->ssl_conn->ssl, array, array_len);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

static int
check_package(const uint8_t *endhash, const uint8_t *endid, const uint8_t *package, uint32_t len)
{
	SetupArray *a;
	uint8_t hash[SHA_DIGEST_LENGTH], result[SHA_DIGEST_LENGTH];
	uint32_t i;
	int ret;
	cleanup_stack_init;
	if (memcmp(endid, package, SHA_DIGEST_LENGTH)) {
		return -1;
	}
	a = setup_array__unpack(NULL, len - SHA_DIGEST_LENGTH, package + SHA_DIGEST_LENGTH);
	if (a == NULL) {
		return -1;
	}
	cleanup_stack_push(sa_array_cleanup_helper, a);
	ret = validate_setup_array(a);
	if (ret != 0) {
		cleanup_stack_free_all();
		return -1;
	}
	bzero(result, SHA_DIGEST_LENGTH);
	for (i = 0; i < a->n_slots; i++) {
		SHA(a->slots[i].data, a->slots[i].len, hash);
		xor(result, hash, SHA_DIGEST_LENGTH);
	}
	if (!memcmp(result, endhash, SHA_DIGEST_LENGTH)) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_free_all();
	return 0;
}

static struct xkeys **
generate_path_keys(const struct setup_path *path)
{
	int i, cnt;
	struct xkeys **keys;
	cleanup_stack_init;
	keys = calloc(path->nxnodes,  sizeof (struct xkeys *));
	if (keys == NULL) {
		return NULL;
	}
	cnt = 0;
	cleanup_stack_push(free, keys);
	for(i = 0; i < path->nnodes; i++) {
		if (path->sps[i].flags & X_NODE) {
			keys[cnt] = generate_conn_keys(path->sps[i].nkeys, path->sps[i].startkey, path->sps[i].salt);
			if (keys[cnt] == NULL) {
				cleanup_stack_free_all();
				return NULL;
			}
			cleanup_stack_push(free, keys[cnt]->ivs);
			cleanup_stack_push(free, keys[cnt]->keys);
			cleanup_stack_push(free, keys[cnt]);
			cnt++;
		}
	}
	assert(cnt == path->nxnodes);
	if (path->is_reverse_path) {
		reverse_array(keys, path->nxnodes, sizeof (struct xkeys *));
	}
	/* keep allocs in case of success */
	return keys;
}

static struct path *
construct_path(const struct config *config, int want_entrypath, int reserve_ap)
{
	int ret, i, x_idx;
	uint32_t outsize;
	uint8_t *package, *array;
	struct setup_path *path;
	struct path *p;
	struct ssl_connection *path_conn;
	struct awaited_connection *wait;

	if (config->nynodes < 3 * config->nxnodes - 2 || config->nxnodes +
	    config->nynodes > 0xef) {
		return NULL;
	}

	path = create_struct_setup_path(config, want_entrypath, reserve_ap);
	if (path == NULL) {
		return NULL;
	}
	ret = get_nodes_from_db(path->nodes, config->nxnodes + config->nynodes);
	if (ret) {
		delete_struct_setup_path(path);
		return NULL;
	}
	build_xy_path(path);
	ret = generate_path_construction_keys(path);
	if (ret) {
		delete_struct_setup_path(path);
		return NULL;
	}

	generate_setup_packages(config, path, 1);
	array = pack_setup_packages(path, &outsize, 1);
	if (array == NULL) {
		delete_struct_setup_path(path);
		return NULL;
	}
	wait = register_wait_connection(path->sps[path->nnodes - 2].next_ip, path->sps[path->nnodes - 1].next_id);
	if (wait == NULL) {
		delete_struct_setup_path(path);
		return NULL;
	}
	ret = send_setup_array(path, config, array, outsize, 1);
	free(array);
	if (ret) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	ret = wait_for_connection(wait, TMOUT);
	if (ret != 0) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	if (! X509_compare_mixed(path->sps[path->nnodes - 2].next_communication_certificate_flat, wait->incoming_conn->peer_cert)) {
		delete_struct_setup_path(path);
		return NULL;
	}
	if (wait->len < SHA_DIGEST_LENGTH) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	ret = check_package(path->endhash, path->sps[path->nnodes - 1].next_id, wait->incoming_package, wait->len);
	if (ret != 0) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	generate_setup_packages(config, path, 2);
	array = pack_setup_packages(path, &outsize, 2);
	if (array == NULL) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	ret = send_setup_array(path, config, array, outsize, 2);
	free(array);
	if (ret) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	package = read_package(wait->incoming_conn->ssl, &outsize);
	if (package == NULL) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	if (outsize < SHA_DIGEST_LENGTH) {
		free_awaited_connection(wait);
		free(package);
		delete_struct_setup_path(path);
		return NULL;
	}
	ret = check_package(path->endhash, path->sps[path->nnodes - 1].next_id, package, outsize);
	free(package);
	if (ret != 0) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	for (i = path->nnodes - 1; i >= 0; i--) {
		if (path->sps[i].flags & X_NODE) {
			break;
		}
	}
	free_awaited_connection(wait);
	if (path->is_reverse_path) {
		wait = register_wait_connection(path->sps[i - 1].next_ip, path->sps[i].next_id);
		if (wait == NULL) {
			delete_struct_setup_path(path);
			return NULL;
		}
	}
	ret = send_x_package(path, config);
	if (ret != 0) {
		free_awaited_connection(wait);
		delete_struct_setup_path(path);
		return NULL;
	}
	p = new_path();
	if (p == NULL) {
		delete_struct_setup_path(path);
		free_awaited_connection(wait);
		return NULL;
	}
	p->ap = path->ap;
	if (path->is_reverse_path) {
		for (x_idx = path->nnodes - 1; x_idx >= 0; x_idx--) {
			if (path->sps[x_idx].flags & X_NODE) {
				memcpy(p->peer_id, path->sps[x_idx].next_id, SHA_DIGEST_LENGTH);
				p->peer_ip = strdup(path->nodes[x_idx].ip);
				if (p->peer_ip == NULL) {
					delete_struct_setup_path(path);
					free_awaited_connection(wait);
					free_path(p);
					return NULL;
				}
				p->peer_port = (path->nodes[x_idx].port);
				break;
			}
		}
		ret = wait_for_connection(wait, TMOUT);
		if (ret != 0) {
			delete_struct_setup_path(path);
			free_awaited_connection(wait);
			free_path(p);
			return NULL;

		}
		if (! X509_compare(path->nodes[x_idx].communication_certificate, wait->incoming_conn->peer_cert)) {
			free_awaited_connection(wait);
			delete_struct_setup_path(path);
			free_path(p);
			return NULL;
		}
		path_conn = wait->incoming_conn;
		wait->incoming_conn = NULL;
		free_awaited_connection(wait);
		p->xkeys = generate_path_keys(path);
		delete_struct_setup_path(path);
	} else {
		for (x_idx = 0; x_idx < path->nnodes; x_idx++) {
			if (path->sps[x_idx].flags & X_NODE) {
				memcpy(p->peer_id, path->sps[x_idx].prev_id, SHA_DIGEST_LENGTH);
				p->peer_ip = strdup(path->nodes[x_idx].ip);
				if (p->peer_ip == NULL) {
					free_path(p);
					return NULL;
				}
				p->peer_port = (path->nodes[x_idx].port);
				break;
			}
		}
		p->xkeys = generate_path_keys(path);
		path_conn = path->ssl_conn;
		delete_struct_setup_path2(path, 1);
	}
	assert(p->xkeys);
	p->conn = path_conn;
	p->nkeys = config->nxnodes;
	p->is_entrypath = want_entrypath;
	return p;
}

struct path *
construct_entry_path(const struct config *config)
{
	return construct_path(config, 1, 0);
}

struct path *
construct_reserve_ap_path(const struct config *config)
{
	return construct_path(config, 0, 1);
}

struct path *
construct_exit_path(const struct config *config)
{
	return construct_path(config, 0, 0);
}

void
free_path(struct path *path)
{
	int i;
	if (path->conn != NULL) {
		free_ssl_connection(path->conn);
	}
	if (path->xkeys != NULL) {
		for (i = 0; i < path->nkeys; i++) {
			if (path->xkeys[i]->keys != NULL) {
				free(path->xkeys[i]->keys);
			}
			if (path->xkeys[i]->ivs != NULL) {
				free(path->xkeys[i]->ivs);
			}
			free(path->xkeys[i]);
		}
		free(path->xkeys);
	}
	if (path->peer_ip != NULL) {
		free(path->peer_ip);
	}
	free(path);
}
