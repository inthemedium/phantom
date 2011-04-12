#include "x509_flat.h"

X509 *
read_x509_from_x509_flat(const struct X509_flat *fx)
{
	BIO *in;
	X509 *x;
	in = BIO_new_mem_buf(fx->data, fx->len);
	if (in == NULL) {
		return NULL;
	}
	x = PEM_read_bio_X509(in, NULL, 0, NULL);
	BIO_free(in);
	return x;
}

struct X509_flat *
new_X509_flat(void)
{
	struct X509_flat *x = malloc(sizeof (struct X509_flat));
	if (x == NULL) {
		return NULL;
	}
	x->data = NULL;
	return x;
}

void
free_X509_flat(struct X509_flat *x)
{
	if (x->data != NULL) {
		free(x->data);
	}
	free(x);
}

struct X509_flat *
read_x509_from_file_flat(const char *path)
{
	struct stat statbuf;
	int ret, have_read, fd;
	struct X509_flat *x = new_X509_flat();
	ret = stat(path, &statbuf);
	if (ret != 0) {
		return NULL;
	}
	x->data = malloc(statbuf.st_size);
	if (x->data == NULL) {
		return NULL;
	}
	x->len = statbuf.st_size;
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		free_X509_flat(x);
		return NULL;
	}
	have_read = 0;
	while (have_read < x->len) {
		ret = read(fd, x->data + have_read, x->len - have_read);
		if (ret < 0) {
			free_X509_flat(x);
			close(fd);
			return NULL;
		}
		have_read += ret;
	}
	assert(x->len == have_read);
	close(fd);
	return x;
}

uint8_t *
serialize_X509_flat(const struct X509_flat *x)
{
	int i;
	uint8_t *buf = malloc(x->len + 4);
	if (buf == NULL) {
		return NULL;
	}
	serialize_32_t(x->len, buf);
	for (i = 0; i < x->len; i++) {
		buf[i + 4] = x->data[i];
	}
	return buf;
}

struct X509_flat *
deserialize_X509_flat(const uint8_t *serialized)
{
	int len, i;
	struct X509_flat *x = new_X509_flat();
	if (x == NULL) {
		return NULL;
	}
	len = deserialize_32_t(serialized);
	x->data = malloc(len);
	if (x->data == NULL) {
		free_X509_flat(x);
		return NULL;
	}
	for (i = 0; i < len; i++) {
		x->data[i] = serialized[i + 4];
	}
	x->len = len;
	return x;
}

int
X509_serialized_size(const struct X509_flat *x)
{
	return x->len + 4;
}

struct X509_flat *
flatten_X509(X509 *x)
{
	struct X509_flat *out;
	int ret;
	BUF_MEM *bptr;
	BIO *mem;

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		return NULL;
	}
	ret = PEM_write_bio_X509(mem, x);
	if (ret == 0) {
		BIO_free(mem);
		return NULL;
	}
	out = new_X509_flat();
	if (out == NULL)  {
		BIO_free(mem);
		return NULL;
	}
	BIO_get_mem_ptr(mem, &bptr);
	assert(BIO_set_close(mem, BIO_NOCLOSE) == 1);
	BIO_free(mem);
	out->len = bptr->length;
	out->data = malloc(bptr->length);
	if (out->data == NULL) {
		BUF_MEM_free(bptr);
		return NULL;
	}
	memcpy(out->data, bptr->data, bptr->length);
	BUF_MEM_free(bptr);
	return out;
}

int
X509_compare(X509 *a, X509 *b)
{
	int ret;
	struct X509_flat *af, *bf;
	af = flatten_X509(a);
	if (af == NULL) {
		return 0;
	}
	bf = flatten_X509(b);
	if (bf == NULL) {
		free(af);
		return 0;
	}
	ret = X509_compare_flat(af, bf);
	free_X509_flat(af);
	free_X509_flat(bf);
	return ret;
}

int
X509_compare_mixed(struct X509_flat *a, X509 *b)
{
	int ret;
	struct X509_flat *bf;
	bf = flatten_X509(b);
	if (bf == NULL) {
		return 0;
	}
	ret = X509_compare_flat(a, bf);
	free_X509_flat(bf);
	return ret;
}

int
X509_compare_flat(struct X509_flat *a, struct X509_flat *b)
{
	if (b->len != a->len) {
		return 0;
	}
	return ! memcmp(a->data, b->data, b->len);
}

int
X509_hash(X509 *c, uint8_t *buf)
{
	struct X509_flat *f;
	assert(c);
	assert(buf);
	f = flatten_X509(c);
	if (f == NULL) {
		return -1;
	}
	SHA1(f->data, f->len, buf);
	free_X509_flat(f);
	return 0;
}

X509 *
clone_cert(X509 *x)
{
	struct X509_flat *f;
	X509 *r;
	f = flatten_X509(x);
	if (f == NULL) {
		return NULL;
	}
	r = read_x509_from_x509_flat(f);
	free_X509_flat(f);
	return r;
}
