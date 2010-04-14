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
 * Somewhat general purpose tool for cbtreedb. It can dump and load many
 * databases with the standard signature and appversion, and uint16_t, uint32_t
 * or uint64_t keys. However, databases with special keys or order relations
 * cannot be handled by this tool.
 */

#include "stx-cbtreedb.h"

#include <iostream>
#include <fstream>
//#include <math.h>
#include <errno.h>
#include <assert.h>

static const char* toolsignature = "cbtreedb";
static const uint32_t toolappversion = 0;

typedef stx::CBTreeDB< uint16_t, std::less<uint16_t>, 1024, toolappversion > cbtreedb_type_u16l_1024;
typedef stx::CBTreeDB< uint32_t, std::less<uint32_t>, 1024, toolappversion > cbtreedb_type_u32l_1024;
typedef stx::CBTreeDB< uint64_t, std::less<uint64_t>, 1024, toolappversion > cbtreedb_type_u64l_1024;

typedef stx::CBTreeDB< uint16_t, std::less<uint16_t>, 2048, toolappversion > cbtreedb_type_u16l_2048;
typedef stx::CBTreeDB< uint32_t, std::less<uint32_t>, 2048, toolappversion > cbtreedb_type_u32l_2048;
typedef stx::CBTreeDB< uint64_t, std::less<uint64_t>, 2048, toolappversion > cbtreedb_type_u64l_2048;

typedef stx::CBTreeDB< uint32_t, std::greater<uint32_t>, 1024, toolappversion > cbtreedb_type_u16g_1024;
typedef stx::CBTreeDB< uint32_t, std::greater<uint32_t>, 1024, toolappversion > cbtreedb_type_u32g_1024;
typedef stx::CBTreeDB< uint64_t, std::greater<uint64_t>, 1024, toolappversion > cbtreedb_type_u64g_1024;

typedef stx::CBTreeDB< uint16_t, std::greater<uint16_t>, 2048, toolappversion > cbtreedb_type_u16g_2048;
typedef stx::CBTreeDB< uint32_t, std::greater<uint32_t>, 2048, toolappversion > cbtreedb_type_u32g_2048;
typedef stx::CBTreeDB< uint64_t, std::greater<uint64_t>, 2048, toolappversion > cbtreedb_type_u64g_2048;

class ProgressCounter
{
private:
    /// the current number
    unsigned long long	count;

    /// the output stream to use
    std::ostream&	os;

public:
    explicit inline ProgressCounter(unsigned long long initial = 0,
				    std::ostream& outputstream = std::cerr)
	: count(initial), os(outputstream)
    {
    }

    // add one to the counter and output if necessary
    inline void	step()
    {
	count++;
	
	if (count % 10000 == 0) {
	    (os << ".").flush();
	}
	if (count % 100000 == 0) {
	    (os << (count / 1000) << "k").flush();
	}
    }

    inline unsigned long long value() const
    {
	return count;
    }
};

template <typename cbtreedb>
struct OperationLoadRandom
{
    static int run(std::istream& input, const char* outputfile)
    {
	typename cbtreedb::Writer writer;
	writer.SetSignature(toolsignature);

	uint32_t len;
	std::string key, value;

	ProgressCounter counter;

	while( input.read(reinterpret_cast<char*>(&len), sizeof(len)) )
	{
	    if (len == 0) {
		std::cerr << std::endl
			  << "Loaded " << counter.value() << " items." << std::endl;
		break;
	    }

	    counter.step();

	    // load key data

	    key.resize(len);

	    if ( !input.read((char*)key.data(), len) ) {
		std::cerr << "Error reading key data: " << strerror(errno) << std::endl;
		return -1;
	    }

	    // read value size and load data

	    if ( !input.read((char*)&len, sizeof(len)) ) {
		std::cerr << "Error reading value length: " << strerror(errno) << std::endl;
		return -1;
	    }

	    value.resize(len);

	    if ( !input.read((char*)value.data(), len) ) {
		std::cerr << "Error reading value data: " << strerror(errno) << std::endl;
		return -1;
	    }

	    // check key length

	    if (key.size() > sizeof(typename cbtreedb::key_type))
	    {
		std::cerr << "Error reading key-value pair: key length is larger than database key type." << std::endl;
	    }

	    typename cbtreedb::key_type dbkey = 0;
	    memcpy(&dbkey, key.data(), key.size());

	    writer.Add(dbkey, value);
	}

	std::ofstream dbfile(outputfile);
	writer.Write(dbfile);

	return 0;
    }
};

template <typename cbtreedb>
struct OperationLoadSequential
{
    static int run(std::istream& input, const char* outputfile)
    {
	typename cbtreedb::WriterSequential writer;
	writer.SetSignature(toolsignature);

	uint32_t len;
	std::string key, value;

	ProgressCounter counter1;

	if (!input.seekg(0, std::ios::beg)) {
	    std::cerr << "Error seeking in input stream: " << strerror(errno) << std::endl;
	    return -1;
	}

	// phase 1: declare keys

	while( input.read(reinterpret_cast<char*>(&len), sizeof(len)) )
	{
	    if (len == 0) {
		std::cerr << std::endl
			  << "Declared " << counter1.value() << " items." << std::endl;
		break;
	    }

	    counter1.step();

	    // load key data

	    key.resize(len);

	    if ( !input.read((char*)key.data(), len) ) {
		std::cerr << "Error reading key data: " << strerror(errno) << std::endl;
		return -1;
	    }

	    // read value size and ignore value data

	    if ( !input.read((char*)&len, sizeof(len)) ) {
		std::cerr << "Error reading value length: " << strerror(errno) << std::endl;
		return -1;
	    }

	    if ( !input.ignore(len) ) {
		std::cerr << "Error skipping value data: " << strerror(errno) << std::endl;
		return -1;
	    }

	    // check key length

	    if (key.size() > sizeof(typename cbtreedb::key_type))
	    {
		std::cerr << "Error reading key-value pair: key length is larger than database key type." << std::endl;
	    }

	    typename cbtreedb::key_type dbkey = 0;
	    memcpy(&dbkey, key.data(), key.size());

	    writer.Add(dbkey, len);
	}

	std::ofstream dbfile(outputfile);
	writer.WriteHeader(dbfile);

	input.clear();	// clears error flags before seek.

	if (!input.seekg(0, std::ios::beg)) {
	    std::cerr << "Error rewinding input stream: " << strerror(errno) << std::endl;
	    return -1;
	}

	// phase 2: write value data to db

	ProgressCounter counter2;

	while( input.read(reinterpret_cast<char*>(&len), sizeof(len)) )
	{
	    if (len == 0) {
		std::cerr << std::endl
			  << "Wrote " << counter2.value() << " items." << std::endl;
		break;
	    }

	    counter2.step();

	    // load key data

	    key.resize(len);

	    if ( !input.read((char*)key.data(), len) ) {
		std::cerr << "Error reading key data: " << strerror(errno) << std::endl;
		return -1;
	    }

	    // read value size and ignore value data

	    if ( !input.read((char*)&len, sizeof(len)) ) {
		std::cerr << "Error reading value length: " << strerror(errno) << std::endl;
		return -1;
	    }

	    value.resize(len);

	    if ( !input.read((char*)value.data(), len) ) {
		std::cerr << "Error reading value data: " << strerror(errno) << std::endl;
		return -1;
	    }

	    // check key length

	    if (key.size() > sizeof(typename cbtreedb::key_type))
	    {
		std::cerr << "Error reading key-value pair: key length is larger than database key type." << std::endl;
	    }

	    typename cbtreedb::key_type dbkey = 0;
	    memcpy(&dbkey, key.data(), key.size());

	    writer.WriteValue(dbkey, value);
	}

	writer.WriteFinalize();

	return 0;
    }
};

template < template<typename cbtreedb> class Operation >
int OperationLoad(std::istream& inputstream, const char* outputfile, const std::string& dbformat)
{
    if (dbformat == "u16l-1024") {
	return Operation<cbtreedb_type_u16l_1024>::run(inputstream, outputfile);
    }
    else if (dbformat == "u32l-1024") {
	return Operation<cbtreedb_type_u32l_1024>::run(inputstream, outputfile);
    }
    else if (dbformat == "u64l-1024") {
	return Operation<cbtreedb_type_u64l_1024>::run(inputstream, outputfile);
    }
    else if (dbformat == "u16l-2048") {
	return Operation<cbtreedb_type_u16l_2048>::run(inputstream, outputfile);
    }
    else if (dbformat == "u32l-2048") {
	return Operation<cbtreedb_type_u32l_2048>::run(inputstream, outputfile);
    }
    else if (dbformat == "u64l-2048") {
	return Operation<cbtreedb_type_u64l_2048>::run(inputstream, outputfile);
    }
    else if (dbformat == "u16g-1024") {
	return Operation<cbtreedb_type_u16g_1024>::run(inputstream, outputfile);
    }
    else if (dbformat == "u32g-1024") {
	return Operation<cbtreedb_type_u32g_1024>::run(inputstream, outputfile);
    }
    else if (dbformat == "u64g-1024") {
	return Operation<cbtreedb_type_u64g_1024>::run(inputstream, outputfile);
    }
    else if (dbformat == "u16g-2048") {
	return Operation<cbtreedb_type_u16g_2048>::run(inputstream, outputfile);
    }
    else if (dbformat == "u32g-2048") {
	return Operation<cbtreedb_type_u32g_2048>::run(inputstream, outputfile);
    }
    else if (dbformat == "u64g-2048") {
	return Operation<cbtreedb_type_u64g_2048>::run(inputstream, outputfile);
    }
    else
    {
	std::cerr << "Invalid dbformat: " << dbformat << std::endl;
	return -1;
    }
}

template <typename cbtreedb>
struct OperationDumpBinary
{
    static bool run(const char* /* dbformat */, std::istream& dbstream)
    {
	typename cbtreedb::Reader reader;
	reader.SetSignature(toolsignature);

	if (!reader.Open(dbstream)) {
	    return false;
	}
	std::cerr << "ok." << std::endl;

	std::cerr << "Database contains " << reader.Size() << " items." << std::endl;

	typename cbtreedb::key_type key;
	std::string value;

	for(unsigned int index = 0; index < reader.Size(); ++index)
	{
	    if (reader.GetIndex(index, key, value) == 0) {
		std::cerr << "Error reading index " << index << std::endl;
	    }

	    uint32_t klen = sizeof(key);
	    uint32_t vlen = value.size();

	    std::cout.write(reinterpret_cast<char*>(&klen), sizeof(klen));
	    std::cout.write(reinterpret_cast<char*>(&key), sizeof(key));

	    std::cout.write(reinterpret_cast<char*>(&vlen), sizeof(vlen));
	    std::cout << value;
	}

	uint32_t zerolen = 0;
	std::cout.write(reinterpret_cast<char*>(&zerolen), sizeof(zerolen));
	std::cout.write(reinterpret_cast<char*>(&zerolen), sizeof(zerolen));

	return true;
    }
};

template <typename cbtreedb>
struct OperationDumpText
{
    static bool run(const char* /* dbformat */, std::istream& dbstream)
    {
	typename cbtreedb::Reader reader;
	reader.SetSignature(toolsignature);

	if (!reader.Open(dbstream)) {
	    return false;
	}
	std::cerr << "ok." << std::endl;

	std::cerr << "Database contains " << reader.Size() << " items." << std::endl;

	typename cbtreedb::key_type key;
	std::string value;

	for(unsigned int index = 0; index < reader.Size(); ++index)
	{
	    if (reader.GetIndex(index, key, value) == 0) {
		std::cerr << "Error reading index " << index << std::endl;
	    }

	    std::cout << "key " << key << " value length " << value.size() << ":" << std::endl
		      << value << std::endl;
	}

	return true;
    }
};

template <typename cbtreedb>
struct OperationVerify
{
    static bool run(const char* dbformat, std::istream& dbstream)
    {
	typename cbtreedb::Reader reader;
	reader.SetSignature(toolsignature);

	std::string errorstring;
	if (!reader.Open(dbstream,&errorstring)) {
	    std::cout << "err: " << errorstring << std::endl;
	    return false;
	}
	std::cerr << "ok." << std::endl;

	std::cerr << "Database format " << dbformat << std::endl;

	std::cerr << "Database contains " << reader.Size() << " items." << std::endl;

	std::cerr << "Key size: " << sizeof(typename cbtreedb::key_type) << std::endl;
	std::cerr << "B-tree page size: " << cbtreedb::BTreePageSize << std::endl;
	std::cerr << "B-tree leaf node slots: " << cbtreedb::LeafNodeNumKeys << std::endl;
	std::cerr << "B-tree inner node slots: " << cbtreedb::InnerNodeNumKeys << std::endl;
	std::cerr << "B-tree levels: " << reader.GetSignature().btree_levels << std::endl;
	std::cerr << "B-tree leaves: " << reader.GetSignature().btree_leaves << std::endl;
	std::cerr << "B-tree total size: " << reader.GetSignature().btree_size << std::endl;
	std::cerr << "Total value area size: " << reader.GetSignature().value_size << std::endl;
	
	(std::cerr << "Verifying btree checksum: ").flush();
	if (!reader.VerifyBTreeChecksum()) {
	    std::cerr << "failed!" << std::endl;
	    return true;
	}
	std::cerr << "ok." << std::endl;

	(std::cerr << "Verifying btree structure: ").flush();
	if (!reader.VerifyBTree()) {
	    std::cerr << "failed!" << std::endl;
	    return true;
	}
	std::cerr << "ok." << std::endl;

	(std::cerr << "Verifying value data checksum: ").flush();
	if (!reader.VerifyValueChecksum()) {
	    std::cerr << "failed!" << std::endl;
	    return true;
	}
	std::cerr << "ok." << std::endl;

	return true;
    }
};

template < template<typename cbtreedb> class Operation >
int OperationTestTypes(const char* dbfilename)
{
    std::ifstream dbstream(dbfilename);

    (std::cerr << "Opening database: ").flush();

    if (Operation<cbtreedb_type_u16l_1024>::run("u16l-1024", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u32l_1024>::run("u32l-1024", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u64l_1024>::run("u64l-1024", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u16l_2048>::run("u16l-2048", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u32l_2048>::run("u32l-2048", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u64l_2048>::run("u64l-2048", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u16g_1024>::run("u16g-1024", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u32g_1024>::run("u32g-1024", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u64g_1024>::run("u64g-1024", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u16g_2048>::run("u16g-2048", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u32g_2048>::run("u32g-2048", dbstream))
	return 0;

    if (Operation<cbtreedb_type_u64g_2048>::run("u64g-2048", dbstream))
	return 0;

    std::cerr << "failed: could not open database." << std::endl;
    return -1;
}

int Usage()
{
    std::cout << "Usage: cbtreedb-tool <operation> [parameter...]" << std::endl
	      << "Operations: " << std::endl
	      << std::endl
	      << "load <input file> <output file> [format]" << std::endl
	      << "  Creates a new database from the binary input file using the random Writer" << std::endl
	      << "  class and writes it to the output file. The input file may also be \"-\" for" << std::endl
	      << "  stdin. The database format may be one of:" << std::endl
	      << "" << std::endl
	      << "  u16l-1024, u32l-1024, u64l-1024, u16l-2048, u32l-2048, u64l-2048," << std::endl
	      << "  u16g-1024, u32g-1024, u64g-1024, u16g-2048, u32g-2048, u64g-2048" << std::endl
	      << "  " << std::endl
	      << "  where" << std::endl
	      << "    - u16, u32 and u64 stand for uint16_t, uint32_t or uint64_t keys," << std::endl
	      << "    - l or g stand for std::less or std::greater ordering, and" << std::endl
	      << "    - 1024 or 2048 specifies the page size." << std::endl
	      << "" << std::endl
	      << "  The default is u32l-1024." << std::endl
	      << "" << std::endl
	      << "load-seq <input file> <output file> [format]" << std::endl
	      << "  Creates a new database just like \"load\" but using the WriterSequential" << std::endl
	      << "  class. Therefore the input key sequence must be in ascending order and the" << std::endl
	      << "  input stream must be seekable (unlike stdin)." << std::endl
	      << "" << std::endl
	      << "dump-binary <file>" << std::endl
	      << "  Opens a database outputs all key-value pairs as a binary sequence to stdout." << std::endl
	      << "" << std::endl
	      << "dump-text <file>" << std::endl
	      << "  Opens a database outputs all key-value pairs as a text sequence to stdout." << std::endl
	      << "" << std::endl
	      << "verify <file>" << std::endl
	      << "  Opens a database created with this tool and verifies internal checksums." << std::endl
	      << "" << std::endl
	      << "" << std::endl
	      << "Binary key-value pair streams used by the tool follow an easy common format." << std::endl
	      << "Both key and value data fields are prefixed with an uint32_t specifying the" << std::endl
	      << "immediately following field's size. All pairs in a stream are concatenated and" << std::endl
	      << "the sequence is terminated with two uint32_t equaling zero, as no key can have" << std::endl
	      << "zero length. Thus the data stream follows the schema:" << std::endl
	      << "" << std::endl
	      << "[len/4 bytes][key/len bytes][len/4 bytes][value/len bytes]...[0/4 bytes][0/4 bytes]" << std::endl
	      << "" << std::endl
	;	    
    return 0;
}
/*
 */
int main(int argc, char* argv[])
{
    if (argc < 3)
	return Usage();

    std::string op = argv[1];

    if (op == "load")
    {
	if (argc != 4 && argc != 5)
	    return Usage();

	const char* dbformat = (argc == 5) ? argv[4] : "u32l-1024";

	if (strcmp(argv[2], "-") == 0)
	{
	    return OperationLoad<OperationLoadRandom>(std::cin, argv[3], dbformat);
	}
	else
	{
	    std::ifstream inputstream(argv[2]);
	    if (inputstream.bad()) {
		std::cerr << "Could not open input stream to load: " << strerror(errno) << std::endl;
		return -1;
	    }

	    return OperationLoad<OperationLoadRandom>(inputstream, argv[3], dbformat);
	}
    }
    else if (op == "load-seq")
    {
	if (argc != 4 && argc != 5)
	    return Usage();

	const char* dbformat = (argc == 5) ? argv[4] : "u32l-1024";

	if (strcmp(argv[2], "-") == 0)
	{
	    return OperationLoad<OperationLoadSequential>(std::cin, argv[3], dbformat);
	}
	else
	{
	    std::ifstream inputstream(argv[2]);
	    if (inputstream.bad()) {
		std::cerr << "Could not open input stream to load: " << strerror(errno) << std::endl;
		return -1;
	    }

	    return OperationLoad<OperationLoadSequential>(inputstream, argv[3], dbformat);
	}
    }
    else if (op == "dump-binary")
    {
	if (argc != 3)
	    return Usage();

	return OperationTestTypes<OperationDumpBinary>(argv[2]);
    }
    else if (op == "dump-text")
    {
	if (argc != 3)
	    return Usage();

	return OperationTestTypes<OperationDumpText>(argv[2]);
    }
    else if (op == "verify")
    {
	if (argc != 3)
	    return Usage();

	return OperationTestTypes<OperationVerify>(argv[2]);
    }
    else
    {
	return Usage();
    }
}
