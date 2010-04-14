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
 * Test SHA256 class by calculating and comparing a few checksums.
 */

#define CBTREEDB_SELF_VERIFY
#include "stx-cbtreedb.h"

#include <assert.h>

// simple method to access the protected SHA256 class
class CBTreeDBTest : public stx::CBTreeDB<>
{
public:

    static std::string SHA256_digest_hex(const std::string& str)
    {
	return SHA256::digest_hex(str);
    }
};

int main()
{
    assert( CBTreeDBTest::SHA256_digest_hex("") ==
	    "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" );

    assert( CBTreeDBTest::SHA256_digest_hex("test string") ==
	    "D5579C46DFCC7F18207013E65B44E4CB4E2C2298F4AC457BA8F82743F31E930B" );

    assert( CBTreeDBTest::SHA256_digest_hex("0123456789012345678901234567890123456789") ==
	    "FB526CD4AD0EC978C1A9E78F7C0728711139978424D618EB228BE59E21188970" );

    assert( CBTreeDBTest::SHA256_digest_hex("wYHemLvD4RCdRZJc0ac42WAL1SIjaRdd8OxLeAjtOc") ==
	    "0466B66B8A7EDA7891B9394BC1BC2254BA450A850295CC62A43A695999A77DCD" );

    return 0;
}
