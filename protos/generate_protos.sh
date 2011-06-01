#!/bin/bash
SRC=../src
protoc-c --c_out=$SRC *proto
echo -n -e 'PROTOOBJECTS=' > $SRC/protobufobjects
for i in *proto; do echo -n -e "`echo $i | cut -d '.' -f 1`.pb-c.o ";done >> $SRC/protobufobjects
