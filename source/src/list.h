#ifndef __HAVE_LIST_H__
#define __HAVE_LIST_H__
/* all functions take as first argument a pointer to the list head */
#define LIST_init(x)			{(x)->next=(x)->prev=(x);}
#define LIST_is_empty(x)		((x)->next==(x))
#define LIST_insert(x,y)		{((y)->next=(x)->next)->prev=(y); ((x)->next=(y))->prev=(x);}
#define LIST_insert_before(x,y)		{((y)->prev=(x)->prev)->next=(y); ((x)->prev=(y))->next=(x);}
#define LIST_remove(x)			{((x)->prev)->next=(x)->next; ((x)->next)->prev=(x)->prev;}
#define LIST_for_all(x,y,z)		for (y=(x)->next,z=(y)->next;y!=(x);y=z,z=(y)->next)
#define LIST_for_all_backwards(x,y,z)	for (y=(x)->prev,z=(y)->prev;y!=(x);y=z,z=(y)->prev)
#define LIST_clear(x,y)			while ((x)->next!=(x)) { y = *x.next; LIST_remove(y); free(y);}
#endif

#if 0
/*Example for a mergesort implementation on a list owith certain type*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "list.h"

struct element {
	struct element *next, *prev;
	int i;
};

static int
cmp(const void *a, const void *b, void *arg)
{
	const struct element *ia, *ib;
	ia = a;
	ib = b;
	(void) arg;
	return ia->i - ib->i;
}

#define __SORT__TYPE__ struct element
static void
mergesort(__SORT__TYPE__ **list, int (*cmpfunc) (const void *a, const void *b, void *args), void *arg)
{
	__SORT__TYPE__ *p, *q, *e, *t, *oh, *l;
#undef __SORT__TYPE__
	int ni, nm, np, nq, i;
	assert(list);
	l = *list;
	if (l == NULL) {
		return;
	}
	assert(cmpfunc);
	ni = 1;
	while (1) {
		oh = l;
		p = l;
		nm = 0;
		t = NULL;
		l = NULL;
		while (p) {
			nm++;
			np = 0;
			q = p;
			for (i = 0; i < ni; i++) {
				np++;
				q = (q->next == oh) ? NULL : q->next;
				if (q == NULL) {
					break;
				}
			}
			nq = ni;
			while (np > 0 || (nq > 0 && q)) {
				if (np == 0) {
					e = q;
					q = q->next;
					nq--;
					if (q == oh) {
						q = NULL;
					}
				} else if (nq == 0 || q == NULL || cmpfunc(p, q, arg) <= 0) {
					e = p;
					p = p->next;
					np--;
					if (p == oh) {
						p = NULL;
					}
				} else {
					e = q;
					q = q->next;
					nq--;
					if (q == oh) {
						q = NULL;
					}
				}
				if (t) {
					t->next = e;
				} else {
					l = e;
				}
				e->prev = t;
				t = e;
			}
			p = q;
		}
		t->next = l;
		l->prev = t;
		if (nm <= 1) {
			*list = l;
			return;
		}
		ni <<= 1;
	}
}
#endif
