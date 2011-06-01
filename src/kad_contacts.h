#ifndef __HAVE_KAD_CONTACTS_H__
#define __HAVE_KAD_CONTACTS_H__

#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include "kademlia.h"
#include "x509_flat.h"

int save_contacts(const char *filename, struct kad_table *table);
int restore_contacts(const char *filename, struct kad_node_info *contacts);

#endif
