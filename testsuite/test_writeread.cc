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
 * Extensively test Writer, WriterSequential and Reader
 * classes. Creates databases using different number of items and
 * different key_types. "Stores" databases to stringstreams and reads
 * them back using all access functions in Reader.
 */

#define CBTREEDB_SELF_VERIFY
#include "stx-cbtreedb.h"

#include <iostream>
#include <sstream>
#include <assert.h>

template <typename cbtreedb>
std::string run_writer(unsigned int items,
		       typename cbtreedb::key_type (*key_mapping)(unsigned int idx, unsigned int items) )
{
    std::cout << "items " << items << " -> ";

    // write new database using Writer

    typename cbtreedb::Writer writer;
    writer.SetSignature("cbtestdb");

    for(unsigned int i = 0; i <= items; ++i)
    {
	typename cbtreedb::key_type key = key_mapping(i, items);

	writer.Add(2*key, &key, sizeof(key));
    }

    assert( writer.Size() == items+1 );

    std::ostringstream testdb;
    writer.Write(testdb);

    std::string dbstr = testdb.str();

    std::cout << "dbsize " << dbstr.size() << std::endl;

    return dbstr;
}

template <typename cbtreedb>
std::string run_writersequential(unsigned int items,
				 typename cbtreedb::key_type (*key_mapping)(unsigned int idx, unsigned int items) )

{
    std::cout << "items " << items << " -> ";

    // write new database using WriterSequential

    typename cbtreedb::WriterSequential writer;
    writer.SetSignature("cbtestdb");

    for(unsigned int i = 0; i <= items; ++i)
    {
	// phase 1: declare key and datasize mappings.

	typename cbtreedb::key_type key = key_mapping(i, items);

	writer.Add(2*key, sizeof(key));
    }

    std::ostringstream testdb;

    writer.WriteHeader(testdb); // write header and btree

    for(unsigned int i = 0; i <= items; ++i)
    {
	// phase 2: write value objects

	typename cbtreedb::key_type key = key_mapping(i, items);

	writer.WriteValue(2*key, &key, sizeof(key));
    }

    assert( writer.Size() == items+1 );

    writer.WriteFinalize();

    std::string dbstr = testdb.str();

    std::cout << "dbsize " << dbstr.size() << std::endl;

    return dbstr;
}

template <typename cbtreedb>
void run_reader(unsigned int items, const std::string& dbstr,
		typename cbtreedb::key_type (*key_mapping)(unsigned int idx, unsigned int items) )
{
    typename cbtreedb::Reader reader;
    reader.SetSignature("cbtestdb");

    typename cbtreedb::PageCache cache(128);
    reader.SetPageCache(&cache);

    std::istringstream testdb(dbstr);
    reader.Open(testdb);

    assert( reader.Verify() );

    assert( reader.VerifyBTree() ); // these are actually included in Verify().
    assert( reader.VerifyBTreeChecksum() );
    assert( reader.VerifyValueChecksum() );

    assert( reader.Size() == items+1 );

    for(unsigned int i = 0; i < 2*items + 2; ++i)
    {
	if (i % 2 == 0)
	    assert( reader.Exists(i) );
	else
	    assert( !reader.Exists(i) );
    }

    for(unsigned int i = 0; i < 2*items + 2; ++i)
    {
	std::string str;
	assert( reader.Lookup(i, str) || i % 2 == 1 );

	if ( i % 2 == 0 )
	    assert( *reinterpret_cast<const uint32_t*>(str.data()) == static_cast<uint32_t>(i/2) );
	else
	    assert( str.empty() );

	uint32_t value;
	assert( reader.Lookup(i, &value, sizeof(value)) || i % 2 == 1 );

	if ( i % 2 == 0 )
	    assert( value == i/2 );

	if ( i % 2 == 0 )
	{
	    uint32_t i2 = i/2;
	    assert( reader[i] == std::string(reinterpret_cast<char*>(&i2), sizeof(i2)) );
	}
	else
	{
	    assert( reader[i] == std::string() );
	}
    }

    typename cbtreedb::Reader reader2 = reader;

    for(unsigned int i = 0; i <= items; ++i)
    {
	uint32_t key;
	uint32_t value;
	std::string outvalue;

	typename cbtreedb::key_type expectedkey = key_mapping(i,items);

	assert(reader2.GetIndex(i, key) == 4);
	assert(key == 2 * expectedkey);

	assert(reader2.GetIndex(i, key, &value, sizeof(value)) == 4);
	assert(key == 2 * expectedkey);
	assert(value == expectedkey);

	assert(reader2.GetIndex(i, key, outvalue) == 4);
	assert(key == 2 * expectedkey);
	assert(outvalue == std::string(reinterpret_cast<char*>(&expectedkey), sizeof(expectedkey)));
    }

    reader.Close();
}

uint32_t key_identity(unsigned int idx, unsigned int)
{
    return idx;
}

uint32_t key_reverse(unsigned int idx, unsigned int items)
{
    return items - idx;
}

int main()
{
    const unsigned int maxitems = 32768;

    std::cout << "Running random writer and reader tests" << std::endl;

    for(unsigned int items = 0; items < maxitems * 32; items*=2)
    {
	typedef stx::CBTreeDB<> cbtreedb;

	std::string dbstr = run_writer<cbtreedb>(items, key_identity);

	run_reader<cbtreedb>(items, dbstr, key_identity);

	if (items < 1) ++items;
    }

    std::cout << "Running sequential writer and reader tests" << std::endl;

    for(unsigned int items = 0; items < maxitems; items*=2)
    {
	typedef stx::CBTreeDB<> cbtreedb;

	std::string dbstr = run_writersequential<cbtreedb>(items, key_identity);

	run_reader<cbtreedb>(items, dbstr, key_identity);

	if (items < 1) ++items;
    }

    std::cout << "Running reverse-order random writer and reader tests" << std::endl;

    for(unsigned int items = 0; items < maxitems; items*=2)
    {
	typedef stx::CBTreeDB< uint32_t, std::greater<uint32_t> > cbtreedb;

	std::string dbstr = run_writer<cbtreedb>(items, key_identity);

	run_reader<cbtreedb>(items, dbstr, key_reverse);

	if (items < 1) ++items;
    }

    std::cout << "Running reverse-order sequential writer and reader tests" << std::endl;

    for(unsigned int items = 0; items < maxitems; items*=2)
    {
	typedef stx::CBTreeDB< uint32_t, std::greater<uint32_t> > cbtreedb;

	std::string dbstr = run_writersequential<cbtreedb>(items, key_reverse);

	run_reader<cbtreedb>(items, dbstr, key_reverse);

	if (items < 1) ++items;
    }

    return 0;
}
