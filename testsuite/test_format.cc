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
 * Freeze database format. Two databases are frozen and included with
 * this test case. Both class configurations are reproduced and the
 * same items inserted. The resulting databases are compared against
 * the frozen database files, both Writer and WriterSequential must
 * produce databases equal to the frozen reference files. Also test
 * error checking in Open() by attempting to load incompatible files.
 */

#define CBTREEDB_SELF_VERIFY
#include "stx-cbtreedb.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <assert.h>
#include <stdlib.h>

static const unsigned int items = 10000;

template <typename cbtreedb>
void run_test_random(const std::string& dbname)
{
    std::cout << "Creating test database using random writer." << std::endl;

    typename cbtreedb::Writer writer;
    writer.SetSignature("cbtestdb");

    for(unsigned int i = 0; i <= items; ++i)
    {
	writer.Add(2*i, &i, sizeof(i));
    }

    // write new database into string object

    std::ostringstream testdb;
    writer.Write(testdb);

    std::string testdbstr = testdb.str();
    // std::cout << "dbsize " << testdbstr.size() << std::endl;

    // read reference database from file
      
    std::string refdbstr;

    {
	std::ifstream ifdb((AM_TOP_SRCDIR "/testsuite/" + dbname).c_str());

	if (!ifdb.good()) {
	    ifdb.open(("testsuite/" + dbname).c_str());
	}

	char buffer[32*1024];
	do
	{
	    ifdb.read(buffer, sizeof(buffer));
	    refdbstr.append(buffer, ifdb.gcount());
	}
	while ( ifdb.good() && !ifdb.eof() );
    }

    // compare reference db and created db

    if (testdbstr != refdbstr)
    {
	std::cout << "Reference database does not match!" << std::endl;

	std::ofstream ofdb((dbname + "-new").c_str());
	ofdb << testdbstr;
	ofdb.close();

	assert( testdbstr == refdbstr );
    }
}

template <typename cbtreedb>
void run_test_sequential(const std::string& dbname)
{
    std::cout << "Creating test database using sequential writer." << std::endl;

    typename cbtreedb::WriterSequential writer;
    writer.SetSignature("cbtestdb");

    for(unsigned int i = 0; i <= items; ++i)
    {
	// phase 1: declare key and valuesize mappings.
	writer.Add(2*i, sizeof(i));
    }

    std::ostringstream testdb;
    
    writer.WriteHeader(testdb); // write header and btree

    for(unsigned int i = 0; i <= items; ++i)
    {
	// phase 2: write value objects
	writer.WriteValue(2*i, &i, sizeof(i));
    }

    writer.WriteFinalize();

    std::string testdbstr = testdb.str();
    // std::cout << "dbsize " << testdbstr.size() << std::endl;

    // read reference database from file
      
    std::string refdbstr;

    {
	std::ifstream ifdb((AM_TOP_SRCDIR "/testsuite/" + dbname).c_str());

	if (!ifdb.good()) {
	    ifdb.open(("testsuite/" + dbname).c_str());
	}

	char buffer[32*1024];
	do
	{
	    ifdb.read(buffer, sizeof(buffer));
	    refdbstr.append(buffer, ifdb.gcount());
	}
	while ( ifdb.good() && !ifdb.eof() );
    }

    // compare reference db and created db

    if (testdbstr != refdbstr)
    {
	std::cout << "Reference database does not match!" << std::endl;

	std::ofstream ofdb((dbname + "-new").c_str());
	ofdb << testdbstr;
	ofdb.close();

	assert( testdbstr == refdbstr );
    }
}

template <typename cbtreedb>
void run_test_open(const std::string& dbname, const std::string& expectederrorstring)
{
    // read database from file
      
    std::string dbstr;

    {
	std::ifstream ifdb((AM_TOP_SRCDIR "/testsuite/" + dbname).c_str());

	if (!ifdb.good()) {
	    ifdb.open(("testsuite/" + dbname).c_str());
	}

	char buffer[32*1024];
	do
	{
	    ifdb.read(buffer, sizeof(buffer));
	    dbstr.append(buffer, ifdb.gcount());
	}
	while ( ifdb.good() && !ifdb.eof() );
    }

    assert(dbstr.size());
    // std::cout << "dbsize " << dbstr.size() << std::endl;

    // create reader object

    typename cbtreedb::Reader reader;
    reader.SetSignature("cbtestdb");

    typename cbtreedb::PageCache cache(128);
    reader.SetPageCache(&cache);

    std::istringstream testdb(dbstr);
    std::string errorstring;

    if (! reader.Open(testdb,&errorstring) )
    {
	if (errorstring != expectederrorstring)
	{
	    std::cout << "Open errorstring mismatched: " << std::endl
		      << "Got: " << errorstring << std::endl
		      << "Expected: " << expectederrorstring << std::endl;
	    abort();		
	}
	return;
    }

    assert( reader.Verify() );
    assert( reader.Size() == items+1 );
}

int main()
{
    // check binary format compatibility with two common configurations

    run_test_random< stx::CBTreeDB<uint32_t, std::less<uint32_t>, 1024> >("test_format1.db");
    run_test_sequential< stx::CBTreeDB<uint32_t, std::less<uint32_t>, 1024> >("test_format1.db");

    run_test_random< stx::CBTreeDB<uint64_t, std::less<uint64_t>, 2048> >("test_format2.db");
    run_test_sequential< stx::CBTreeDB<uint64_t, std::less<uint64_t>, 2048> >("test_format2.db");

    // check error when opening database with wrong configurations

    run_test_open< stx::CBTreeDB<uint32_t, std::less<uint32_t>, 1024> >
	("test_format1.db", "");

    run_test_open< stx::CBTreeDB<uint32_t, std::less<uint32_t>, 2048> >
	("test_format1.db", "Database not compatible with this reader: page sizes mismatch.");

    run_test_open< stx::CBTreeDB<uint64_t, std::less<uint64_t>, 1024> >
	("test_format1.db", "Database not compatible with this reader: key sizes mismatch.");

    run_test_open< stx::CBTreeDB<uint32_t, std::greater<uint32_t>, 1024> >
	("test_format1.db", "Database not compatible with this reader: root keys order mismatches.");


    run_test_open< stx::CBTreeDB<uint64_t, std::less<uint64_t>, 2048> >
	("test_format2.db", "");

    run_test_open< stx::CBTreeDB<uint64_t, std::less<uint64_t>, 1024> >
	("test_format2.db", "Database not compatible with this reader: page sizes mismatch.");

    run_test_open< stx::CBTreeDB<uint32_t, std::less<uint32_t>, 2048> >
	("test_format2.db", "Database not compatible with this reader: key sizes mismatch.");

    run_test_open< stx::CBTreeDB<uint64_t, std::greater<uint64_t>, 2048> >
	("test_format2.db", "Database not compatible with this reader: root keys order mismatches.");

    return 0;
}
