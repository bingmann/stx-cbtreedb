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

#include "stx-cbtreedb.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <assert.h>
#include <math.h>

int main()
{
    // declare cbtreedb parameters
    typedef stx::CBTreeDB< uint32_t, std::less<uint32_t> > cbtreedb;

    const unsigned int items = 64;

#if 1
    // write items into constant db "example1.db"
    {
	// create random order writer object
	cbtreedb::Writer writer;

	// add some key-values into writer map
	for(unsigned int i = 0; i < items; ++i)
	{
	    std::ostringstream oss;
	    oss << "value " << i;

	    writer.Add(i*i, oss.str());
	}

	// write out database via ofstream
	std::ofstream testdb("example1.db");
	writer.Write(testdb);
    }
#else
    // alternatively write database using WriterSequential
    {
	// create sequential order writer object
	cbtreedb::WriterSequential writer;

	// phase 1: declare key and values lengths
	for(unsigned int i = 0; i < items; ++i)
	{
	    writer.Add(i*i, strlen("value ") + (i > 0 ? (log10(i) + 1) : 1));
	}

	// write out header and B-tree to database via ofstream
	std::ofstream testdb("example1.db");
	writer.WriteHeader(testdb);

	// phase 2: deliver key and value data
	for(unsigned int i = 0; i < items; ++i)
	{
	    std::ostringstream oss;
	    oss << "value " << i;

	    writer.WriteValue(i*i, oss.str());
	}

	// finalize database by updating signature page
	writer.WriteFinalize();
    }
#endif

    // read back items from db
    {
	cbtreedb::Reader reader;

	// set up page cache to keep hot pages in memory
	cbtreedb::PageCache cache(128);
	reader.SetPageCache(&cache);

	// attach an ifstream to the reader and open db
	std::ifstream testdb("example1.db");
	std::string errorstring;
	if (!reader.Open(testdb, &errorstring))
	{
	    std::cout << "Error loading database: " << errorstring << std::endl;
	    return -1;
	}	   

	// full verification (takes long for big dbs)
	assert( reader.Verify() );

	// iterate through all items in the database
	std::cout << "Full listing:" << std::endl;
	for(unsigned int i = 0; i < reader.Size(); ++i)
	{
	    uint32_t key;
	    std::string value;

	    reader.GetIndex(i, key, value);

	    std::cout << "key " << key << " -> " << value << ", ";
	}
	std::cout << std::endl;

	// pick out some items
	std::cout << "sqrt(2500) -> " << reader[2500] << std::endl;
	std::cout << "sqrt(2501) -> " << reader[2501] << std::endl;
	std::cout << "sqrt(2601) -> " << reader[2601] << std::endl;

	// check existance of keys
	std::cout << "isSquare(2704) -> " << reader.Exists(2704) << std::endl;
	std::cout << "isSquare(2705) -> " << reader.Exists(2705) << std::endl;

	// full lookup function
	std::string out;

	if (reader.Lookup(2808, out))
	    std::cout << "Lookup 2808 -> " << out << " (was found.)" << std::endl;
	else
	    std::cout << "Lookup 2808 has failed." << std::endl;

	if (reader.Lookup(2809, out))
	    std::cout << "Lookup 2809 -> " << out << " (was found.)" << std::endl;
	else
	    std::cout << "Lookup 2809 has failed." << std::endl;
    }

    return 0;
}
