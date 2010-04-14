// -*- mode: c++; fill-column: 79 -*-
// $Id$

/*
 * STX Constant B-Tree Database Template Classes v0.7.0
 * Copyright (C) 2010 Timo Bingmann
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Force instantiation of different class configurations to test
 * compilation of all functions with different template
 * parameters. Also tests class with a struct as key_type.
 */

#define CBTREEDB_SELF_VERIFY
#include "stx-cbtreedb.h"

#include <iostream>
#include <sstream>
#include <assert.h>

// forced instantiations

template class stx::CBTreeDB<>;

template class stx::CBTreeDB< uint32_t, std::greater<uint32_t> >;

template class stx::CBTreeDB< uint64_t, std::greater<uint64_t> >;

struct key_struct
{
    uint8_t	i8;
    uint32_t	i32;
}	
    __attribute__((packed));

struct key_struct_less
{
    inline bool operator()(const key_struct& a, const key_struct& b)
    {
	return a.i8 < b.i8;
    }
};

template class stx::CBTreeDB< key_struct, key_struct_less >;

int main()
{
    // check some instance parameters
    {
	typedef stx::CBTreeDB<> cbtreedb;

	assert(cbtreedb::BTreePageSize == 1024);
	//assert(sizeof(cbtreedb::LeafNode) == 1024);
	assert(cbtreedb::LeafNodeNumKeys == 126);
	assert(cbtreedb::LeafNodeFiller == 0);
	assert(cbtreedb::InnerNodeNumKeys == 254);
	assert(cbtreedb::InnerNodeFiller == 0);
    }
    {
	typedef stx::CBTreeDB<uint64_t> cbtreedb;

	assert(cbtreedb::BTreePageSize == 1024);
	//assert(sizeof(cbtreedb::LeafNode) == 1024);
	assert(cbtreedb::LeafNodeNumKeys == 84);
	assert(cbtreedb::LeafNodeFiller == 0);
	assert(cbtreedb::InnerNodeNumKeys == 127);
	assert(cbtreedb::InnerNodeFiller == 0);
    }
    {
	typedef stx::CBTreeDB<uint64_t, std::less<uint64_t>, 2048> cbtreedb;

	assert(cbtreedb::BTreePageSize == 2048);
	//assert(sizeof(cbtreedb::LeafNode) == 2048);
	assert(cbtreedb::LeafNodeNumKeys == 169);
	assert(cbtreedb::LeafNodeFiller == 4);
	assert(cbtreedb::InnerNodeNumKeys == 255);
	assert(cbtreedb::InnerNodeFiller == 0);
    }

    return 0;
}
