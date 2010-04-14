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
 * Check PageCache behaviour by adding fake pages step by step and
 * checking cache contents and LRU-order after each Store() or
 * Retrieve(). Also test the cache using its internal Verify()
 * function.
 */

#define CBTREEDB_SELF_VERIFY
#include "stx-cbtreedb.h"

#include <assert.h>

class CBTreeDBTest : public stx::CBTreeDB<>
{
public:

    void test1_pagecache()
    {
	PageCache pc(8);

	void* btreeid = reinterpret_cast<void*>(0x12345678);

	BTreePage p1;

	pc.Store(btreeid, 1, p1);
	pc.Store(btreeid, 2, p1);
	pc.Store(btreeid, 3, p1);
	pc.Store(btreeid, 4, p1);
	assert( pc.Verify() );

	{
	    std::vector< std::pair<void*, uint32_t> > pagelist = pc.GetPagelist();

	    assert( pagelist.size() == 4 );
	    assert( pagelist[0].first == btreeid && pagelist[0].second == 4 );
	    assert( pagelist[1].first == btreeid && pagelist[1].second == 3 );
	    assert( pagelist[2].first == btreeid && pagelist[2].second == 2 );
	    assert( pagelist[3].first == btreeid && pagelist[3].second == 1 );
	}

	pc.Retrieve(btreeid, 2, p1);
	assert( pc.Verify() );

	{
	    std::vector< std::pair<void*, uint32_t> > pagelist = pc.GetPagelist();

	    assert( pagelist.size() == 4 );
	    assert( pagelist[0].first == btreeid && pagelist[0].second == 2 );
	    assert( pagelist[1].first == btreeid && pagelist[1].second == 4 );
	    assert( pagelist[2].first == btreeid && pagelist[2].second == 3 );
	    assert( pagelist[3].first == btreeid && pagelist[3].second == 1 );
	}

	pc.Store(btreeid, 5, p1);
	pc.Store(btreeid, 6, p1);
	pc.Store(btreeid, 7, p1);
	pc.Store(btreeid, 8, p1);
	assert( pc.Verify() );

	{
	    std::vector< std::pair<void*, uint32_t> > pagelist = pc.GetPagelist();

	    assert( pagelist.size() == 8 );
	    assert( pagelist[0].first == btreeid && pagelist[0].second == 8 );
	    assert( pagelist[1].first == btreeid && pagelist[1].second == 7 );
	    assert( pagelist[2].first == btreeid && pagelist[2].second == 6 );
	    assert( pagelist[3].first == btreeid && pagelist[3].second == 5 );
	    assert( pagelist[4].first == btreeid && pagelist[4].second == 2 );
	    assert( pagelist[5].first == btreeid && pagelist[5].second == 4 );
	    assert( pagelist[6].first == btreeid && pagelist[6].second == 3 );
	    assert( pagelist[7].first == btreeid && pagelist[7].second == 1 );
	}

	pc.Store(btreeid, 9, p1);
	assert( pc.Verify() );
	
	{
	    std::vector< std::pair<void*, uint32_t> > pagelist = pc.GetPagelist();

	    assert( pagelist.size() == 8 );
	    assert( pagelist[0].first == btreeid && pagelist[0].second == 9 );
	    assert( pagelist[1].first == btreeid && pagelist[1].second == 8 );
	    assert( pagelist[2].first == btreeid && pagelist[2].second == 7 );
	    assert( pagelist[3].first == btreeid && pagelist[3].second == 6 );
	    assert( pagelist[4].first == btreeid && pagelist[4].second == 5 );
	    assert( pagelist[5].first == btreeid && pagelist[5].second == 2 );
	    assert( pagelist[6].first == btreeid && pagelist[6].second == 4 );
	    assert( pagelist[7].first == btreeid && pagelist[7].second == 3 );
	}

	pc.Store(btreeid, 10, p1);
	pc.Store(btreeid, 6, p1);
	assert( pc.Verify() );
	
	{
	    std::vector< std::pair<void*, uint32_t> > pagelist = pc.GetPagelist();

	    assert( pagelist.size() == 8 );
	    assert( pagelist[0].first == btreeid && pagelist[0].second == 6 );
	    assert( pagelist[1].first == btreeid && pagelist[1].second == 10 );
	    assert( pagelist[2].first == btreeid && pagelist[2].second == 9 );
	    assert( pagelist[3].first == btreeid && pagelist[3].second == 8 );
	    assert( pagelist[4].first == btreeid && pagelist[4].second == 7 );
	    assert( pagelist[5].first == btreeid && pagelist[5].second == 5 );
	    assert( pagelist[6].first == btreeid && pagelist[6].second == 2 );
	    assert( pagelist[7].first == btreeid && pagelist[7].second == 4 );
	}
    }


    void test2_pagecache()
    {
	PageCache pc(32);

	void* btreeid = reinterpret_cast<void*>(0x12345678);

	BTreePage p1;

	for (unsigned int i = 0; i < 1000; ++i)
	{
	    if (i % 2 == 0)
	    {
		pc.Store(btreeid, (i * 0x548A1B71) % 53, p1);
	    }
	    else
	    {
		pc.Retrieve(btreeid, (i * 0x548A1B71) % 53, p1);
	    }

	    assert( pc.Verify() );
	}
    }
};

int main()
{
    CBTreeDBTest().test1_pagecache();
    CBTreeDBTest().test2_pagecache();
    return 0;
}
