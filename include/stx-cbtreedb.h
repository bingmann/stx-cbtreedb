// -*- mode: c++; fill-column: 79 -*-
// $Id$

/** \file stx-cbtreedb.h
 * Contains all classes of the constant B-tree database implementation.
 */

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

#ifndef _STX_CBTREEDB_H_
#define _STX_CBTREEDB_H_

#include <string.h>
#include <stdint.h>

#include <stdexcept>
#include <vector>
#include <map>
#include <iostream>

/// STX - Some Template Extensions namespace
namespace stx {

// *** Compile-time assertion macros borrowed from Boost

#ifndef STX_STATIC_ASSERT

template <bool> struct STATIC_ASSERTION_FAILURE;
template <> struct STATIC_ASSERTION_FAILURE<true> { enum { value = 1 }; };
template <int x> struct static_assert_test {};

#define STX_MACRO_JOIN(X,Y) STX_MACRO_DO_JOIN(X,Y)
#define STX_MACRO_DO_JOIN(X,Y) STX_MACRO_DO_JOIN2(X,Y)
#define STX_MACRO_DO_JOIN2(X,Y) X##Y

#define STX_STATIC_ASSERT(A) \
    typedef static_assert_test<sizeof(STATIC_ASSERTION_FAILURE< static_cast<bool>(A) >)> \
	STX_MACRO_JOIN(static_assert_typedef_, __LINE__)

#endif

/**
 * @brief Template super-class enclosing all classes which can operate on a
 * constant B-tree database file.
 *
 * By parameterizing this class an instance of all sub-classes is created. The
 * parameters described important database parameters and database files should
 * be read and written using the _same_ class parameters!
 *
 * The first template parameter is the key type, which must be an integral,
 * fixed-length type like uint32_t or a struct.
 * 
 * The second template parameter is the order functional used to sort the keys,
 * it must form a total order relation over the keys.
 * 
 * The size of B-tree pages containing nodes are defined by the third
 * parameter. The number of key slots in each node is calculated from this
 * number and sizeof(_Key). There are some obvious constraints on the
 * relationship of page size and key size which are checked by compile-time
 * assertions.
 *
 * The fourth template parameter is an uint32_t version number stored in the
 * signature page of the database. It can be used by an application to mark its
 * own database. When opening databases this parameter must match the
 * signature.
 *
 * For more information see http://idlebox.net/2010/stx-cbtreedb/
 */
template < typename _Key = uint32_t,
	   typename _Compare = std::less<_Key>,
	   unsigned int _BTreePageSize = 1024,
	   uint32_t _AppVersionId = 0>
class CBTreeDB
{
public:
    // *** Template Parameters

    /// first template parameter: the key type of the B-tree. This must be an
    /// integral, fixed-length type as it is used in arrays in the tree nodes.
    typedef _Key	key_type;

    /// second template parameter: key comparison function object type.
    typedef _Compare	key_compare;

    /// third template parameter: B-tree page size. Usually 1024 or 2048.
    static const unsigned int BTreePageSize = _BTreePageSize;

    /// fourth template parameter: application-defined 32-bit identifier to
    /// mark database format or version.
    static const uint32_t AppVersionId = _AppVersionId;

    // *** Structure parameters calculated from page size

    /// size of fields before key+offset array in LeafNode and additional
    /// offset at end.
    static const unsigned int LeafNodeHead = 2 * sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint32_t);

    /// number of key+offsets in each LeafNode
    static const unsigned int LeafNodeNumKeys = (BTreePageSize - LeafNodeHead) / (sizeof(key_type) + sizeof(uint32_t));

    STX_STATIC_ASSERT( LeafNodeNumKeys >= 1 );

    /// number of unused fill bytes in each LeafNode
    static const unsigned int LeafNodeFiller = BTreePageSize - LeafNodeHead - LeafNodeNumKeys * (sizeof(key_type) + sizeof(uint32_t));

    /// size of fields before key array in InnerNode
    static const unsigned int InnerNodeHead = 2 * sizeof(uint16_t) + sizeof(uint32_t);

    /// number of keys in each InnerNode
    static const unsigned int InnerNodeNumKeys = (BTreePageSize - InnerNodeHead) / sizeof(key_type);

    STX_STATIC_ASSERT( InnerNodeNumKeys >= 2 );

    /// number of unused fill bytes in each InnerNode
    static const unsigned int InnerNodeFiller = BTreePageSize - InnerNodeHead - InnerNodeNumKeys * sizeof(key_type);

public:
    /**
     * Our own exception class derived from std::runtime_error.
     */
    class Exception : public std::runtime_error
    {
    public:
	/// Create new exception object with error message.
	explicit Exception(const std::string& str)
	    : std::runtime_error("CBTreeDB: " + str)
	{
	}
    };

    /// Instead of assert() we use this macro to throw exceptions. These could
    /// be disabled for production releases.
#define CBTREEDB_ASSERT(x) do { if (!(x)) throw(Exception("Assertion failed: " #x)); } while(0)

    /// Short macro to throw exceptions if a program logic expression
    /// fails. These must not be disabled in production releases as they may
    /// depend on user input.
#define CBTREEDB_CHECK(x,msg) do { if (!(x)) throw(Exception(msg)); } while(0)

public:
    /**
     * @brief Signature page which heads all cbtreedb files.
     *
     * It contains a signature and many important fields to correctly access
     * the database file. Due to disk page alignment reasons, the signature
     * block is stored with a full B-tree page size.
     */
    struct SignaturePage
    {
	char		signature[8];	///< "cbtreedb" or custom string
	uint32_t	header_crc32;	///< CRC32 of following bytes
	uint32_t	version;	///< 0x00010000
	uint32_t	app_version_id;	///< custom id defined by template

	uint32_t	items;		///< key-value pairs in db
	uint32_t	key_size;	///< sizeof(key_type)

	uint64_t	btree_offset;	///< b-tree offset in file
	uint64_t	btree_size;	///< b-tree total size in bytes
	uint64_t	btree_firstleaf; ///< offset of first leaf in file
	uint32_t	btree_pagesize;	///< size of b-tree nodes
	uint32_t	btree_levels;	///< number of levels in tree
	uint32_t	btree_leaves;	///< number of leaf nodes in tree
	uint8_t		btree_sha256[32]; ///< SHA256 digest of all tree nodes

	uint64_t	value_offset;	///< file offset of value data area
	uint64_t	value_size;	///< total size of value data area
	uint8_t		value_sha256[32]; ///< SHA256 digest of all value data
    }
	__attribute__((packed));

    /// Fixed signature page size: always equal to the B-tree page.
    static const unsigned int SignaturePageSize = BTreePageSize;

    STX_STATIC_ASSERT( sizeof(SignaturePage) <= BTreePageSize );

protected:
    /**
     * @brief Leaf node structure of the B-tree leaf pages.
     *
     * Each leaf node contains a key array and an array of relative value
     * offsets. It does not contain the size of the value elements, because
     * these can be computed from two successive relative offsets. This works
     * for the last offset only because of the extra offset of the successor
     * value item in the next leaf. The value offsets are relative to a
     * starting 64-bit offset, because all leaf's data items are stored in
     * order.
     */
    struct LeafNode
    {
	/// level of this leaf node -> always 0.
	uint16_t	level;

	/// number of used slots in the arrays.
	uint16_t	slots;

	/// base of value offsets enumerated in array.
	uint64_t	baseoffset;

	/// key array of ascending key in this leaf.
	key_type	keys[LeafNodeNumKeys];

	/// file offset of value data associated with key.
	uint32_t	offsets[LeafNodeNumKeys+1];

	/// unused zero filled bytes to fill the page
	uint8_t		filler[LeafNodeFiller];

	/// Initializes structure with zero.
	inline explicit LeafNode()
	    : level(0), slots(0), baseoffset(0)
	{
	    memset(keys, 0, sizeof(keys));
	    memset(offsets, 0, sizeof(offsets));
	    std::fill(filler+0, filler+sizeof(filler), 0);
	}

	/// Returns true if no more keys can be added.
	inline bool IsFull() const
	{
	    return (slots >= LeafNodeNumKeys);
	}

	/// Returns the currently last key in the node
	inline const key_type& LastKey() const
	{
	    CBTREEDB_ASSERT(slots > 0 && slots < LeafNodeNumKeys+1);
	    return keys[slots-1];
	}
    }
	__attribute__((packed));

    STX_STATIC_ASSERT( sizeof(LeafNode) == BTreePageSize );

    /**
     * @brief Inner node structure of the B-tree inner pages.
     *
     * Each inner node has n+1 children nodes, where n is the number of keys in
     * the node. The n+1 children nodes are stored consecutively starting at
     * childrenoffset.
     */
    struct InnerNode
    {
	/// level of this inner node, always > 0.
	uint16_t	level;

	/// number of used slots in the arrays.
	uint16_t	slots;

	/// base offset of child B-tree nodes enumerated by keys.
	uint32_t	childrenoffset;

	/// key array of ascending keys in this inner node.
	key_type	keys[InnerNodeNumKeys];

	/// unused zero filled bytes to fill the page
	uint8_t		filler[InnerNodeFiller];

	/// Initializes structure with zero.
	inline explicit InnerNode(uint16_t level_)
	    : level(level_), slots(0)
	{
	    memset(keys, 0, sizeof(keys));
	    std::fill(filler+0, filler+sizeof(filler), 0);
	}

	/// Returns true if no more keys can be added.
	inline bool IsFull() const
	{
	    return (slots >= InnerNodeNumKeys);
	}

	/// Returns the currently last key in the node
	inline const key_type& LastKey() const
	{
	    CBTREEDB_ASSERT(slots > 0 && slots < InnerNodeNumKeys+1);
	    return keys[slots-1];
	}
    }
	__attribute__((packed));

    STX_STATIC_ASSERT( sizeof(InnerNode) == BTreePageSize );

protected:
    /**
     * @brief CRC32 Cyclic redundancy check implementation class.
     *
     * Copied from the Botan-1.6.4 cryptography library.
     */
    class CRC32
    {
    private:
	/// CRC intermediate value
	uint32_t	m_crc;

    public:
	/// Initialize new CRC object
	CRC32()
	{
	    clear();
	}

	/// Clear current CRC object
	void clear()
	{
	    m_crc = 0xFFFFFFFF;
	}

	/// Update this CRC value with new data.
	CRC32& update(const unsigned char* input, uint32_t length)
	{
	    static const uint32_t table[256] = {
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419,
		0x706AF48F, 0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4,
		0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07,
		0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
		0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856,
		0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
		0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
		0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
		0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3,
		0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A,
		0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599,
		0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
		0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190,
		0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
		0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E,
		0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
		0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED,
		0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
		0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3,
		0xFBD44C65, 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
		0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
		0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5,
		0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010,
		0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
		0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17,
		0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6,
		0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615,
		0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
		0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344,
		0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
		0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A,
		0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
		0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1,
		0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C,
		0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
		0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
		0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE,
		0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31,
		0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C,
		0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
		0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B,
		0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
		0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1,
		0x18B74777, 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
		0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 0xA00AE278,
		0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7,
		0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66,
		0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
		0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
		0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8,
		0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B,
		0x2D02EF8D };

	    register uint32_t tmp = m_crc;

	    while(length >= 16)
	    {
		tmp = table[(tmp ^ input[ 0]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 1]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 2]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 3]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 4]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 5]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 6]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 7]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 8]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[ 9]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[10]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[11]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[12]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[13]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[14]) & 0xFF] ^ (tmp >> 8);
		tmp = table[(tmp ^ input[15]) & 0xFF] ^ (tmp >> 8);
		input += 16;
		length -= 16;
	    }

	    for(uint32_t j = 0; j != length; ++j)
		tmp = table[(tmp ^ input[j]) & 0xFF] ^ (tmp >> 8);

	    m_crc = tmp;

	    return *this;
	}

	/// Update this CRC value with new data.
	CRC32& update(const void* input, uint32_t length)
	{
	    return update(reinterpret_cast<const unsigned char*>(input), length);
	}

	/// Return final CRC value of this object.
	uint32_t final() const
	{
	    return (m_crc ^ 0xFFFFFFFF);
	}

	/// Calculate CRC32 digest of bytes in the given range.
	static uint32_t digest(const void* input, uint32_t length)
	{
	    return CRC32().update(input, length).final();
	}

	/// Calculate CRC32 digest of a string.
	static uint32_t digest(const std::string& input)
	{
	    return digest(input.data(), input.size());
	}
    };

protected:
    /**
     * @brief SHA-256 Message Digest implementation class.
     *
     * Copied from the Botan-1.6.4 cryptography library.
     */
    class SHA256
    {
    private:
	/// local typedef from Botan library
	typedef uint8_t byte;

	/// local typedef from Botan library
	typedef uint32_t u32bit;

	/// local typedef from Botan library
	typedef uint64_t u64bit;

	/// length of the resulting digest
	static const u32bit OUTPUT_LENGTH = 32;

	/// block of bytes to process in hash function
	static const u32bit HASH_BLOCK_SIZE = 64;

	/// length of size suffix hashed during finalization
	static const u32bit COUNT_SIZE = 8;

    private:
	u32bit	 	W[64];
	u32bit		digest[8];

	byte		buffer[HASH_BLOCK_SIZE];

	u64bit		count;
	u32bit		position;

    private:
	/// Rotation Functions
	template<typename T> inline T rotate_left(T input, u32bit rot)
	{ return static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot))); }

	/// Rotation Functions
	template<typename T> inline T rotate_right(T input, u32bit rot)
	{ return static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot))); }

	/// Byte Extraction Function
	template<typename T> inline byte get_byte(u32bit byte_num, T input)
	{ return static_cast<byte>(input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3)); }

	/// Byte to Word Conversions
	inline u32bit make_u32bit(byte input0, byte input1, byte input2, byte input3)
	{ return static_cast<u32bit>((static_cast<u32bit>(input0) << 24) |
				     (static_cast<u32bit>(input1) << 16) |
				     (static_cast<u32bit>(input2) <<  8) | input3); }

	/// SHA-256 Rho Function
	inline u32bit rho(u32bit X, u32bit rot1, u32bit rot2, u32bit rot3)
	{
	    return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^
		    rotate_right(X, rot3));
	}

	/// SHA-256 Sigma Function
	inline u32bit sigma(u32bit X, u32bit rot1, u32bit rot2, u32bit shift)
	{
	    return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^ (X >> shift));
	}

	/// SHA-256 F1 Function
	inline void F1(u32bit A, u32bit B, u32bit C, u32bit& D,
		       u32bit E, u32bit F, u32bit G, u32bit& H,
		       u32bit msg, u32bit magic)
	{
	    magic += rho(E, 6, 11, 25) + ((E & F) ^ (~E & G)) + msg;
	    D += magic + H;
	    H += magic + rho(A, 2, 13, 22) + ((A & B) ^ (A & C) ^ (B & C));
	}

	/// SHA-256 Compression Function
	void hash(const byte input[])
	{
	    for(u32bit j = 0; j != 16; ++j)
		W[j] = make_u32bit(input[4*j], input[4*j+1], input[4*j+2], input[4*j+3]);
	    for(u32bit j = 16; j != 64; ++j)
		W[j] = sigma(W[j- 2], 17, 19, 10) + W[j- 7] +
		    sigma(W[j-15],  7, 18,  3) + W[j-16];

	    u32bit A = digest[0], B = digest[1], C = digest[2],
		D = digest[3], E = digest[4], F = digest[5],
		G = digest[6], H = digest[7];

	    F1(A,B,C,D,E,F,G,H,W[ 0],0x428A2F98);
	    F1(H,A,B,C,D,E,F,G,W[ 1],0x71374491);
	    F1(G,H,A,B,C,D,E,F,W[ 2],0xB5C0FBCF);
	    F1(F,G,H,A,B,C,D,E,W[ 3],0xE9B5DBA5);
	    F1(E,F,G,H,A,B,C,D,W[ 4],0x3956C25B);
	    F1(D,E,F,G,H,A,B,C,W[ 5],0x59F111F1);
	    F1(C,D,E,F,G,H,A,B,W[ 6],0x923F82A4);
	    F1(B,C,D,E,F,G,H,A,W[ 7],0xAB1C5ED5);
	    F1(A,B,C,D,E,F,G,H,W[ 8],0xD807AA98);
	    F1(H,A,B,C,D,E,F,G,W[ 9],0x12835B01);
	    F1(G,H,A,B,C,D,E,F,W[10],0x243185BE);
	    F1(F,G,H,A,B,C,D,E,W[11],0x550C7DC3);
	    F1(E,F,G,H,A,B,C,D,W[12],0x72BE5D74);
	    F1(D,E,F,G,H,A,B,C,W[13],0x80DEB1FE);
	    F1(C,D,E,F,G,H,A,B,W[14],0x9BDC06A7);
	    F1(B,C,D,E,F,G,H,A,W[15],0xC19BF174);
	    F1(A,B,C,D,E,F,G,H,W[16],0xE49B69C1);
	    F1(H,A,B,C,D,E,F,G,W[17],0xEFBE4786);
	    F1(G,H,A,B,C,D,E,F,W[18],0x0FC19DC6);
	    F1(F,G,H,A,B,C,D,E,W[19],0x240CA1CC);
	    F1(E,F,G,H,A,B,C,D,W[20],0x2DE92C6F);
	    F1(D,E,F,G,H,A,B,C,W[21],0x4A7484AA);
	    F1(C,D,E,F,G,H,A,B,W[22],0x5CB0A9DC);
	    F1(B,C,D,E,F,G,H,A,W[23],0x76F988DA);
	    F1(A,B,C,D,E,F,G,H,W[24],0x983E5152);
	    F1(H,A,B,C,D,E,F,G,W[25],0xA831C66D);
	    F1(G,H,A,B,C,D,E,F,W[26],0xB00327C8);
	    F1(F,G,H,A,B,C,D,E,W[27],0xBF597FC7);
	    F1(E,F,G,H,A,B,C,D,W[28],0xC6E00BF3);
	    F1(D,E,F,G,H,A,B,C,W[29],0xD5A79147);
	    F1(C,D,E,F,G,H,A,B,W[30],0x06CA6351);
	    F1(B,C,D,E,F,G,H,A,W[31],0x14292967);
	    F1(A,B,C,D,E,F,G,H,W[32],0x27B70A85);
	    F1(H,A,B,C,D,E,F,G,W[33],0x2E1B2138);
	    F1(G,H,A,B,C,D,E,F,W[34],0x4D2C6DFC);
	    F1(F,G,H,A,B,C,D,E,W[35],0x53380D13);
	    F1(E,F,G,H,A,B,C,D,W[36],0x650A7354);
	    F1(D,E,F,G,H,A,B,C,W[37],0x766A0ABB);
	    F1(C,D,E,F,G,H,A,B,W[38],0x81C2C92E);
	    F1(B,C,D,E,F,G,H,A,W[39],0x92722C85);
	    F1(A,B,C,D,E,F,G,H,W[40],0xA2BFE8A1);
	    F1(H,A,B,C,D,E,F,G,W[41],0xA81A664B);
	    F1(G,H,A,B,C,D,E,F,W[42],0xC24B8B70);
	    F1(F,G,H,A,B,C,D,E,W[43],0xC76C51A3);
	    F1(E,F,G,H,A,B,C,D,W[44],0xD192E819);
	    F1(D,E,F,G,H,A,B,C,W[45],0xD6990624);
	    F1(C,D,E,F,G,H,A,B,W[46],0xF40E3585);
	    F1(B,C,D,E,F,G,H,A,W[47],0x106AA070);
	    F1(A,B,C,D,E,F,G,H,W[48],0x19A4C116);
	    F1(H,A,B,C,D,E,F,G,W[49],0x1E376C08);
	    F1(G,H,A,B,C,D,E,F,W[50],0x2748774C);
	    F1(F,G,H,A,B,C,D,E,W[51],0x34B0BCB5);
	    F1(E,F,G,H,A,B,C,D,W[52],0x391C0CB3);
	    F1(D,E,F,G,H,A,B,C,W[53],0x4ED8AA4A);
	    F1(C,D,E,F,G,H,A,B,W[54],0x5B9CCA4F);
	    F1(B,C,D,E,F,G,H,A,W[55],0x682E6FF3);
	    F1(A,B,C,D,E,F,G,H,W[56],0x748F82EE);
	    F1(H,A,B,C,D,E,F,G,W[57],0x78A5636F);
	    F1(G,H,A,B,C,D,E,F,W[58],0x84C87814);
	    F1(F,G,H,A,B,C,D,E,W[59],0x8CC70208);
	    F1(E,F,G,H,A,B,C,D,W[60],0x90BEFFFA);
	    F1(D,E,F,G,H,A,B,C,W[61],0xA4506CEB);
	    F1(C,D,E,F,G,H,A,B,W[62],0xBEF9A3F7);
	    F1(B,C,D,E,F,G,H,A,W[63],0xC67178F2);

	    digest[0] += A; digest[1] += B; digest[2] += C;
	    digest[3] += D; digest[4] += E; digest[5] += F;
	    digest[6] += G; digest[7] += H;
	}

	/// Copy out the digest
	void copy_out(byte output[])
	{
	    for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
		output[j] = get_byte(j % 4, digest[j/4]);
	}

    protected:

	/// Update the hash
	void add_data(const byte input[], u32bit length)
	{
	    count += length;

	    if (position)
	    {
		memcpy(buffer + position, input,
		       std::min(length, sizeof(buffer) - position));

		if(position + length >= HASH_BLOCK_SIZE)
		{
		    hash(buffer);
		    input += (HASH_BLOCK_SIZE - position);
		    length -= (HASH_BLOCK_SIZE - position);
		    position = 0;
		}
	    }

	    while(length >= HASH_BLOCK_SIZE)
	    {
		hash(input);
		input += HASH_BLOCK_SIZE;
		length -= HASH_BLOCK_SIZE;
	    }

	    memcpy(buffer + position, input,
		   std::min(length, sizeof(buffer) - position));

	    position += length;
	}

	/// Write the count bits to the buffer
	void write_count(byte out[])
	{
	    for(u32bit j = 0; j != 8; ++j)
	    {
		out[j+COUNT_SIZE-8] = get_byte(j % 8, 8 * count);
	    }
	}

	/// Finalize a Hash
	void final_result(byte output[OUTPUT_LENGTH])
	{
	    buffer[position] = 0x80;
	    for(u32bit j = position+1; j != HASH_BLOCK_SIZE; ++j)
		buffer[j] = 0;
	    if(position >= HASH_BLOCK_SIZE - COUNT_SIZE)
	    {
		hash(buffer);
		memset(buffer, 0, sizeof(buffer));
	    }
	    write_count(buffer + HASH_BLOCK_SIZE - COUNT_SIZE);

	    hash(buffer);
	    copy_out(output);
	    clear();
	}

    public:
	/// SHA_256 / MDx_HashFunction Constructor
	SHA256()
	{
	    clear();
	}

	/// Clear memory of sensitive data
	void clear() throw()
	{
	    memset(buffer, 0, sizeof(buffer));
	    count = position = 0;

	    memset(W, 0, sizeof(W));
	    digest[0] = 0x6A09E667;
	    digest[1] = 0xBB67AE85;
	    digest[2] = 0x3C6EF372;
	    digest[3] = 0xA54FF53A;
	    digest[4] = 0x510E527F;
	    digest[5] = 0x9B05688C;
	    digest[6] = 0x1F83D9AB;
	    digest[7] = 0x5BE0CD19;
	}

	/// Update this SHA256 calculation with new data.
	SHA256& update(const void* input, uint32_t length)
	{
	    add_data(reinterpret_cast<const unsigned char*>(input), length);
	    return *this;
	}

	/// Return final SHA256 digest of this object in the buffer.
	void final(byte output[OUTPUT_LENGTH])
	{
	    final_result(output);
	}

	/// Return final SHA256 digest of this object as a string.
	std::string final()
	{
	    byte result[OUTPUT_LENGTH];
	    final_result(result);
	    return std::string(reinterpret_cast<char*>(result), OUTPUT_LENGTH);
	}

	/// Returns true if the final SHA256 digest of this object equals the
	/// given data.
	bool final_equals(byte compare[OUTPUT_LENGTH])
	{
	    byte result[OUTPUT_LENGTH];
	    final_result(result);
	    return (memcmp(compare, result, OUTPUT_LENGTH) == 0);
	}

	/// Return final SHA256 digest of this object as a string encoded in
	/// hexadecimal.
	std::string final_hex()
	{
	    byte result[OUTPUT_LENGTH];
	    final_result(result);

	    std::string out(OUTPUT_LENGTH*2, '\0');

	    static const char xdigits[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	    };

	    std::string::iterator oi = out.begin();
	    for (unsigned int i = 0; i < OUTPUT_LENGTH; ++i)
	    {
		*oi++ = xdigits[ (result[i] & 0xF0) >> 4 ];
		*oi++ = xdigits[ (result[i] & 0x0F) ];
	    }

	    return out;
	}

	/// Calculate SHA256 digest of bytes in the given range.
	static std::string digest_bin(const void* input, uint32_t length)
	{
	    return SHA256().update(input, length).final();
	}

	/// Calculate SHA256 digest of a string.
	static std::string digest_bin(const std::string& input)
	{
	    return digest_bin(input.data(), input.size());
	}

	/// Calculate SHA256 digest of bytes in the given range. Result is
	/// encoded in hexadecimal.
	static std::string digest_hex(const void* input, uint32_t length)
	{
	    return SHA256().update(input, length).final_hex();
	}

	/// Calculate SHA256 digest of a string. Result is encoded in
	/// hexadecimal.
	static std::string digest_hex(const std::string& input)
	{
	    return digest_hex(input.data(), input.size());
	}
    };

protected:
    /**
     * @brief BTreePage is a reference-counted buffer holding one page of the
     * B-tree index. 
     *
     * Note that this wrapper object may also contain an invalid/uninitialized
     * page pointer. The enclosed data can be casted to either a LeafNode
     * object or an InnerNode object. The corresponding cast direction is
     * checked against the page's level number..
     */
    class BTreePage
    {
    protected:
	/**
	 * @brief Implementation of BTreePage: holds the data buffer and a
	 * reference counter.
	 */
	struct Impl
	{
	    /// reference counter
	    unsigned int refs;

	    /// data buffer
	    char	data[BTreePageSize];
	};

	/// pointer to reference-counted data buffer object.
	struct Impl*	m_impl;

    public:
	/// Default Constructor: create new invalid page buffer
	BTreePage()
	    : m_impl(NULL)
	{
	}

	/// Copy Constructor: increment reference counter on buffer.
	BTreePage(const BTreePage& btp)
	    : m_impl(btp.m_impl)
	{
	    if (m_impl)
		++m_impl->refs;
	}

	/// Destructor: decrement reference counter on buffer and possibly
	/// deallocate it.
	~BTreePage()
	{
	    if (m_impl && --m_impl->refs == 0)
		delete m_impl;
	}

	/// Assignment Operator: increment reference counter on buffer.
	BTreePage& operator=(const BTreePage& btp)
	{
	    if (this != &btp)
	    {
		if (m_impl && --m_impl->refs == 0)
		    delete m_impl;

		m_impl = btp.m_impl;

		if (m_impl)
		    ++m_impl->refs;
	    }

	    return *this;
	}

	/// Determine whether the wrapper object contains valid page.
	bool IsValid() const
	{
	    return (m_impl != NULL);
	}

	/// Release enclosed page and initialize a new page buffer.
	void Create()
	{
	    if (m_impl && --m_impl->refs == 0)
		delete m_impl;

	    m_impl = new Impl;
	    m_impl->refs = 1;
	}

	/// Accessor: return enclosed buffer pointer.
	char* GetBuffer()
	{
	    CBTREEDB_ASSERT(m_impl);
	    return m_impl->data;
	}

	/// Return the enclosed node's level in the tree.
	uint16_t GetLevel() const
	{
	    CBTREEDB_ASSERT(m_impl);
	    return reinterpret_cast<InnerNode*>(m_impl->data)->level;
	}

	/// Returns true if the buffer contains a leaf node.
	bool IsLeafNode() const
	{
	    return (GetLevel() == 0);
	}

	/// Return buffer casted as an inner node.
	InnerNode* GetAsInnerNode() const
	{
	    CBTREEDB_ASSERT(m_impl && !IsLeafNode());
	    return reinterpret_cast<InnerNode*>(m_impl->data);
	}

	/// Return buffer casted as a leaf node.
	LeafNode* GetAsLeafNode() const
	{
	    CBTREEDB_ASSERT(m_impl && IsLeafNode());
	    return reinterpret_cast<LeafNode*>(m_impl->data);
	}
    };

protected:
    /**
     * @brief PageCache and PageCacheImpl implement a LRU-strategy cache of
     * B-tree pages used by CBTreeDB reader objects.
     *
     * One cache object can be shared between multiple readers. However, this
     * page cache is not thread safe. You may have to wrap some mutex libraries
     * if needed.
     *
     * The cached pages are put into a hash table for quick lookup by
     * (btreeid,pageid). Simultaneously the HashCells are linked into a doubly
     * chained "LRU"-list with the most recently used page at the head. This
     * allows O(1) algorithms for both Store() and Retrieve() functions. When
     * the maximum number of pages is exceeded, the tail pages of the LRU-list
     * are removed. The drawing below illustrates the data structure used by
     * the class.
     *
     * \htmlonly
     * <div style="text-align: center">
     * <p>Structure of PageCache's arrays and nodes</p>
     * <object type="image/svg+xml" data="drawing-1.svg" style="height: 25em"></object>
     * </div>
     * \endhtmlonly
     */
    class PageCacheImpl
    {
    protected:

	/// reference counter
	unsigned int	m_refs;

	/// maximum number of pages in cache
	unsigned int	m_maxsize;

	/// current number of pages in cache
	unsigned int 	m_size;

#ifdef CBTREEDB_SELF_VERIFY
	/**
	 * @brief counter to tag pages with a virtual LRU timestamp.
	 * This is just for verification purposes and is only used in the
	 * testsuite as the counter may overflow in real applications.
	 */
	uint32_t	m_lrutime;
#endif

	/// Structure for each slot in the cache hash array
	struct HashCell
	{
	    /// pointer forward to next hash cell in bucket
	    struct HashCell	*bucket_next;

	    /// pointer backward to previous hash cell in bucket
	    struct HashCell	*bucket_prev;

	    /// pointer forward in LRU double-linked list
	    struct HashCell	*list_next;

	    /// pointer backward in LRU double-linked list
	    struct HashCell	*list_prev;

#ifdef CBTREEDB_SELF_VERIFY
	    /// virtual LRU timestamp, just for testing.
	    uint32_t	lrutime;
#endif

	    /// b-tree object identifier of page
	    void*	btreeid;

	    /// page identifier withing b-tree
	    uint32_t	pageid;

	    /// page holder object
	    BTreePage	page;
	};

	/// hash cell array holding pointers to active cells
	std::vector<struct HashCell*> m_hasharray;

	/**
	 * @brief sentinel hash cell for LRU double-linked list.
	 * list_next is the head and list_prev is the tail of the list.
	 */
	struct HashCell	m_sentinel;

	/// Simple hash function mapping (btreeid,pageid) -> bucket.
	inline unsigned int hashfunc(void* btreeid, uint32_t pageid)
	{
	    // since hot pageids are usually ascending, I guess this is a
	    // pretty good hash function.
	    return (reinterpret_cast<uint32_t>(btreeid) + pageid) % m_hasharray.size();
	}

    public:
	/// Create a new page cache containg maxsize pages
	explicit PageCacheImpl(unsigned int maxsize)
	    : m_refs(0), m_maxsize(maxsize), m_size(0)
	{
	    m_hasharray.resize(m_maxsize / 2, NULL);

	    m_sentinel.list_prev = m_sentinel.list_next = &m_sentinel;
#ifdef CBTREEDB_SELF_VERIFY
	    m_lrutime = 0;
	    m_sentinel.lrutime = 0;
#endif
	}

	/// Removes all cached pages and destroys cache.
	~PageCacheImpl()
	{
	    Clear();
	}

	/// Increment reference counter by one.
	void RefInc()
	{
	    ++m_refs;
	}

	/// Decrement reference counter by one and return it.
	unsigned int RefDec()
	{
	    return --m_refs;
	}

	/// Remove all pages from the cache and reset status.
	void Clear()
	{
	    // free up hash cells
	    struct HashCell* hc = m_sentinel.list_next;
	    while (hc != &m_sentinel)
	    {
		struct HashCell* nc = hc->list_next;
		delete hc;
		hc = nc;
	    }

	    // zero hash array
	    for (unsigned int i = 0; i < m_hasharray.size(); ++i)
		m_hasharray[i] = NULL;

	    m_sentinel.list_prev = m_sentinel.list_next = &m_sentinel;
	    m_size = 0;
#ifdef CBTREEDB_SELF_VERIFY
	    m_sentinel.lrutime = 0;
	    m_lrutime = 0;
#endif
	}

	/// Store a page object in a cache cell identified by (btreeid,pageid).
	void Store(void* btreeid, uint32_t pageid, const BTreePage& page)
	{
	    // check whether its already in the cache

	    unsigned int h = hashfunc(btreeid, pageid);

	    struct HashCell* hc = m_hasharray[h];

	    while( hc && ! (hc->btreeid == btreeid && hc->pageid == pageid) )
	    {
		// advance in bucket list
		hc = hc->bucket_next;
	    }

	    if ( hc ) // found in cache: unlink from LRU list and place in front
	    {
		if (hc != m_sentinel.list_next)
		{
		    // remove cell wherever it is
		    hc->list_next->list_prev = hc->list_prev;
		    hc->list_prev->list_next = hc->list_next;

		    // place at head
		    hc->list_prev = &m_sentinel;
		    hc->list_next = m_sentinel.list_next;
		    m_sentinel.list_next->list_prev = hc;
		    m_sentinel.list_next = hc;

		    // copy page, it may have changed
		    hc->page = page;

#ifdef CBTREEDB_SELF_VERIFY
		    hc->lrutime = ++m_lrutime;
#endif
		}
		// else hc is the head -> do nothing.
	    }
	    else // not found in cache.
	    {
		// remove last page in LRU list if necessary
		while (m_size >= m_maxsize)
		{
		    struct HashCell* lc = m_sentinel.list_prev;

		    CBTREEDB_ASSERT( lc != &m_sentinel );

		    // unlink from bucket list
		    if (reinterpret_cast<uint32_t>(lc->bucket_prev) > m_hasharray.size())
		    {
			if (lc->bucket_next)
			    lc->bucket_next->bucket_prev = lc->bucket_prev;

			lc->bucket_prev->bucket_next = lc->bucket_next;
		    }
		    else // at first place in bucket list
		    {
			if (lc->bucket_next)
			    lc->bucket_next->bucket_prev = lc->bucket_prev;

			m_hasharray[ reinterpret_cast<uint32_t>(lc->bucket_prev) ] = lc->bucket_next;
		    }

		    // unlink from LRU list
		    lc->list_next->list_prev = lc->list_prev;
		    lc->list_prev->list_next = lc->list_next;

		    delete lc;

		    --m_size;
		}

		// create new hash cell
		hc = new HashCell;

#ifdef CBTREEDB_SELF_VERIFY
		hc->lrutime = ++m_lrutime;
#endif
		hc->btreeid = btreeid;
		hc->pageid = pageid;
		hc->page = page;

		// set hash cell as head of LRU list
		hc->list_prev = &m_sentinel;
		hc->list_next = m_sentinel.list_next;
		m_sentinel.list_next->list_prev = hc;
		m_sentinel.list_next = hc;

		// insert new hash cell to correct bucket
		hc->bucket_prev = reinterpret_cast<HashCell*>( h );
		hc->bucket_next = m_hasharray[h];

		if (m_hasharray[h])
		    m_hasharray[h]->bucket_prev = hc;

		m_hasharray[h] = hc;

		++m_size;
	    }

#ifdef CBTREEDB_SELF_VERIFY
	    CBTREEDB_ASSERT( Verify() );
#endif
	}

	/// Retrieve a cached page identified by (btreeid,pageid). Returns true
	/// if the page was found.
	bool Retrieve(void* btreeid, uint32_t pageid, BTreePage& outpage)
	{
	    // check whether its in the cache

	    unsigned int h = hashfunc(btreeid, pageid);

	    struct HashCell* hc = m_hasharray[h];

	    while( hc && ! (hc->btreeid == btreeid && hc->pageid == pageid) )
	    {
		// advance in bucket list
		hc = hc->bucket_next;
	    }

	    if ( hc ) // found in cache: unlink from LRU list and place in front
	    {
		if (hc != m_sentinel.list_next)
		{
		    // remove cell wherever it is
		    hc->list_next->list_prev = hc->list_prev;
		    hc->list_prev->list_next = hc->list_next;

		    // place at head
		    hc->list_prev = &m_sentinel;
		    hc->list_next = m_sentinel.list_next;
		    m_sentinel.list_next->list_prev = hc;
		    m_sentinel.list_next = hc;

#ifdef CBTREEDB_SELF_VERIFY
		    hc->lrutime = ++m_lrutime;
#endif
		}
		// else hc is the head -> do nothing.

		outpage = hc->page;

#ifdef CBTREEDB_SELF_VERIFY
		CBTREEDB_ASSERT( Verify() );
#endif
		return true;
	    }
	    else
	    {
#ifdef CBTREEDB_SELF_VERIFY
		CBTREEDB_ASSERT( Verify() );
#endif
		return false;
	    }
	}

	/// Change maximum number of pages in cache, note that this does not
	/// immediately have effect.
	void SetMaxSize(unsigned int maxsize)
	{
	    m_maxsize = maxsize;
	}

	/// Return a vector listing all currently contained (btreeid,pageid)
	/// pairs in LRU order. Used by the test cases for verification.
	std::vector< std::pair<void*, uint32_t> > GetPagelist() const
	{
	    std::vector< std::pair<void*, uint32_t> > v;

	    struct HashCell* hc = m_sentinel.list_next;

	    while (hc != &m_sentinel)
	    {
		v.push_back( std::make_pair(hc->btreeid, hc->pageid) );
		hc = hc->list_next;
	    }

	    return v;
	}

	/// Verify the integrity of the LRU list and hash table.
	bool Verify() const
	{
	    { // traverse LRU list forwards

		unsigned int size = 0;
		struct HashCell* hc = m_sentinel.list_next;

		while (hc != &m_sentinel)
		{
		    if (!(hc->list_prev->list_next == hc)) return false;
		    if (!(hc->list_next->list_prev == hc)) return false;
#ifdef CBTREEDB_SELF_VERIFY
		    if (!(hc->lrutime > hc->list_next->lrutime)) return false;
#endif

		    ++size;
		    hc = hc->list_next;
		}

		if (size != m_size) return false;
	    }

	    { // traverse LRU list backwards

		unsigned int size = 0;
		struct HashCell* hc = m_sentinel.list_prev;

		while (hc != &m_sentinel)
		{
		    if (!(hc->list_prev->list_next == hc)) return false;
		    if (!(hc->list_next->list_prev == hc)) return false;
#ifdef CBTREEDB_SELF_VERIFY
		    if (!(hc->lrutime < hc->list_prev->lrutime || hc->list_prev == &m_sentinel)) return false;
#endif

		    ++size;
		    hc = hc->list_prev;
		}

		if (size != m_size) return false;
	    }

	    { // check and count hash cells in buckets

		unsigned int size = 0;

		for (unsigned int b = 0; b < m_hasharray.size(); ++b)
		{
		    struct HashCell* hc = m_hasharray[b];

		    if (!hc) continue;

		    if (!(reinterpret_cast<uint32_t>(hc->bucket_prev) == b)) return false;

		    ++size;

		    while (hc->bucket_next != NULL)
		    {
			if (!(hc->bucket_next->bucket_prev == hc)) return false;

			hc = hc->bucket_next;

			++size;
		    }
		}

		if (size != m_size) return false;
	    }

	    return true;
	}
    };

public:
    /**
     * @brief PageCache and PageCacheImpl implement a LRU-strategy cache of
     * B-tree pages used by CBTreeDB reader objects.
     *
     * One cache object can be shared between multiple readers. However, this
     * page cache is not thread safe. You may have to wrap some mutex libraries
     * if needed.
     *
     * The cached pages are put into a hash table for quick lookup by
     * (btreeid,pageid). Simultaneously the HashCells are linked into a doubly
     * chained "LRU"-list with the most recently used page at the head. This
     * allows O(1) algorithms for both Store() and Retrieve() functions. When
     * the maximum number of pages is exceeded, the tail pages of the LRU-list
     * are removed. The drawing below illustrates the data structure used by
     * the class.
     *
     * \htmlonly
     * <div style="text-align: center">
     * <p>Structure of PageCache's arrays and nodes</p>
     * <object type="image/svg+xml" data="drawing-1.svg" style="height: 25em"></object>
     * </div>
     * \endhtmlonly
     */
    class PageCache
    {
    protected:

	/// pointer to implementation class.
	PageCacheImpl*	m_impl;

    public:
	/// Create a new page cache containg maxsize pages
	explicit PageCache(unsigned int maxpages)
	    : m_impl(new PageCacheImpl(maxpages))
	{
	    m_impl->RefInc();
	}

	/// Copy Constructor: increment reference counter on base object.
	PageCache(const PageCache& pc)
	    : m_impl(pc.m_impl)
	{
	    m_impl->RefInc();
	}

	/// Destructor: decrement reference counter on buffer and possibly
	/// deallocate it.
	~PageCache()
	{
	    if (m_impl->RefDec() == 0)
		delete m_impl;
	}

	/// Assignment Operator: increment reference counter on base object.
	PageCache& operator=(const PageCache& pc)
	{
	    if (this != &pc)
	    {
		if (m_impl->RefDec() == 0)
		    delete m_impl;

		m_impl = pc.m_impl;
		m_impl->RefInc();
	    }

	    return *this;
	}

	/// Remove all pages from the cache and reset status.
	void Clear()
	{
	    return m_impl->Clear();
	}

	/// Store a page object in a cache cell identified by (btreeid,pageid).
	void Store(void* btreeid, uint32_t pageid, const BTreePage& page)
	{
	    return m_impl->Store(btreeid, pageid, page);
	}

	/// Retrieve a cached page identified by (btreeid,pageid). Returns true
	/// if the page was found.
	bool Retrieve(void* btreeid, uint32_t pageid, BTreePage& outpage)
	{
	    return m_impl->Retrieve(btreeid, pageid, outpage);
	}

	/// Change maximum number of pages in cache, note that this does not
	/// immediately have effect.
	void SetMaxSize(unsigned int maxsize)
	{
	    return m_impl->SetMaxSize(maxsize);
	}

	/// Return a vector listing all currently contained (btreeid,pageid)
	/// pairs in LRU order. Used by the test cases for verification.
	std::vector< std::pair<void*, uint32_t> > GetPagelist() const
	{
	    return m_impl->GetPagelist();
	}

	/// Verify the integrity of the LRU list and hash table.
	bool Verify() const
	{
	    return m_impl->Verify();
	}
    };

protected:
    /**
     * @brief Implementation class used to read constant B-tree database files.
     *
     * Refer to \ref sec_architecture and \ref sec_example on how to use this class.
     */
    class ReaderImpl
    {
    protected:

	/// reference counter
	unsigned int	m_refs;

	/// key comparison functional
	key_compare	m_key_less;

	/// signature characters to expect file to begin with.
	char		m_signaturestr[8];

	/// file stream object currently opened.
	std::istream*	m_istream;

	/// signature page read from file
	SignaturePage	m_signature;

	/// pointer to b-tree page cache to used.
	PageCache*	m_pagecache;

	/// Read one B-tree page from the file (or from cache).
	BTreePage ReadIndexPage(uint32_t pageoffset)
	{
	    CBTREEDB_CHECK(pageoffset + m_signature.btree_pagesize <= m_signature.btree_size,
			   "Invalid B-tree page offset to retrieve.");

	    CBTREEDB_ASSERT(m_istream);

	    BTreePage page;

	    if (m_pagecache)
	    {
		if (m_pagecache->Retrieve(this, pageoffset, page))
		    return page;
	    }

	    m_istream->seekg(m_signature.btree_offset + pageoffset);
	    CBTREEDB_CHECK(m_istream->good(), "Could not read B-tree page.");

	    page.Create();

	    m_istream->read(page.GetBuffer(), BTreePageSize);
	    CBTREEDB_CHECK(m_istream->good(), "Could not read B-tree page.");

	    if (m_pagecache)
	    {
		m_pagecache->Store(this, pageoffset, page);
	    }

	    return page;
	}

	/// Read byte range [offset, offset+size) from value data area into the
	/// given buffer.
	bool ReadValueRange(uint64_t offset, void* data, uint32_t size)
	{
	    CBTREEDB_ASSERT(m_istream);

	    if (offset + size > m_signature.value_size) return false;

	    m_istream->seekg(m_signature.value_offset + offset);
	    if (m_istream->bad()) return false;

	    m_istream->read(reinterpret_cast<char*>(data), size);
	    if (m_istream->bad()) return false;

	    return true;
	}

	/// Function to test key equality, constructed from m_key_less.
	bool KeyEqual(const key_type& a, const key_type& b)
	{
	    return !m_key_less(a,b) && !m_key_less(b,a);
	}

	/// Function to test key inequality, constructed from m_key_less.
	bool KeyUnequal(const key_type& a, const key_type& b)
	{
	    return m_key_less(a,b) || m_key_less(b,a);
	}

	/// Find the first key slot containing a greater-or-equal key.
	template <typename NodeType>
	int BinarySearch(const NodeType* node, key_type key)
	{
	    register int lo = 0, hi = node->slots;

	    while (lo < hi)
	    {
		register int mid = (hi + lo) >> 1;

		if (m_key_less(node->keys[mid], key)) {
		    lo = mid + 1;
		}
		else {
		    hi = mid;
		}
	    }

#ifdef CBTREEDB_SELF_VERIFY
	    // verify result using simple linear search
	    {
		int i = 0;
		while(i < node->slots && m_key_less(node->keys[i], key))
		    ++i;

		CBTREEDB_ASSERT(i == lo);
	    }
#endif
	    return lo;
	}

    public:
	/// Create new reader, which is initially set to closed state.
	ReaderImpl(const key_compare& key_less)
	    : m_refs(0), m_key_less(key_less), m_istream(NULL), m_pagecache(NULL)
	{
	    memcpy(m_signaturestr, "cbtreedb", 8);
	}

	/// Increment reference counter by one.
	void RefInc()
	{
	    ++m_refs;
	}

	/// Decrement reference counter by one and return it.
	unsigned int RefDec()
	{
	    return --m_refs;
	}

	/**
	 * Change the database signature (first 8 bytes) from 'cbtreedb' to a
	 * custom string. The signature is always 8 bytes long. Longer strings
	 * are truncated, shorter ones padded with nulls.
	 */
	void SetSignature(const char* newsignature)
	{
	    unsigned int i = 0;
	    for(; i < 8 && newsignature[i]; ++i)
		m_signaturestr[i] = newsignature[i];

	    for(; i < 8; ++i)
		m_signaturestr[i] = 0;
	}

	/**
	 * Attempt to open a cbtreedb database file. Reads and verifies the
	 * signature and initializes the reader. Note that this function does
	 * not through an exception if the file could not be loaded! The
	 * istream object must exist as long as the Reader is used.
	 *
	 * @param file		database file input stream to attach.
	 * @param errortext	in case of error, set to an informative text.
	 * @return		true if loaded and verified correctly.
	 */
	bool Open(std::istream& file, std::string* errortext = NULL)
	{
	    m_istream = NULL;

	    file.seekg(0, std::ios::beg);
	    if (file.bad()) {
		if (errortext) *errortext = "Could not open database.";
		return false;
	    }

	    file.read(reinterpret_cast<char*>(&m_signature), sizeof(m_signature));
	    if (file.bad()) {
		if (errortext) *errortext = "Could not read signature.";
		return false;
	    }

	    if (memcmp(m_signature.signature, m_signaturestr, 8) != 0) {
		if (errortext) *errortext = "Could not verify signature.";
		return false;
	    }

	    if (m_signature.version != 0x00010000) {
		if (errortext) *errortext = "Signature contains unknown version.";
		return false;
	    }
	    
	    if (m_signature.app_version_id != AppVersionId) {
		if (errortext) *errortext = "Signature mismatches application version identifier.";
		return false;
	    }
	    
	    uint32_t crc = CRC32::digest(reinterpret_cast<char*>(&m_signature)+16, sizeof(m_signature)-16);

	    if (m_signature.header_crc32 != crc) {
		if (errortext) *errortext = "Header checksum mismatches.";
		return false;
	    }

	    if (m_signature.key_size != sizeof(key_type)) {
		if (errortext) *errortext  = "Database not compatible with this reader: key sizes mismatch.";
		return false;
	    }

	    if (m_signature.btree_pagesize != BTreePageSize) {
		if (errortext) *errortext  = "Database not compatible with this reader: page sizes mismatch.";
		return false;
	    }

	    // test database compatibility with order relation by checking root
	    // node's key sequence.

	    m_istream = &file;

	    BTreePage root = ReadIndexPage(0);

	    if ( root.IsLeafNode() )
	    {
		LeafNode* leaf = root.GetAsLeafNode();

		for(uint16_t s = 0; s < leaf->slots - 1; ++s)
		{
		    if (!m_key_less(leaf->keys[s], leaf->keys[s+1])) {
			m_istream = NULL;
			if (errortext) *errortext  = "Database not compatible with this reader: root keys order mismatches.";
			return false;
		    }
		}
	    }
	    else
	    {
		InnerNode* inner = root.GetAsInnerNode();

		for(uint16_t s = 0; s < inner->slots - 1; ++s)
		{
		    if (!m_key_less(inner->keys[s], inner->keys[s+1])) {
			m_istream = NULL;
			if (errortext) *errortext  = "Database not compatible with this reader: root keys order mismatches.";
			return false;
		    }
		}
	    }

	    return true;
	}

	/**
	 * Close the opened database.
	 */
	void Close()
	{
	    if (m_istream)
		m_istream = NULL;
	}

	/// Change the currently used page cache object
	void SetPageCache(PageCache* newpagecache)
	{
	    m_pagecache = newpagecache;
	}

	/**
	 * Returns the number of items in the loaded database.
	 */
	uint32_t Size() const
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    return m_signature.items;
	}

	/**
	 * Returns a const reference to the signature page of the currently
	 * loaded database.
	 */
	const SignaturePage& GetSignature() const
	{
	    return m_signature;
	}

    protected:
	/**
	 * Internal function to look down the B-tree and find a key. If found,
	 * returns the offset and size of the corresponding value data area.
	 */
	bool FindKey(const key_type& key, uint64_t& outoffset, uint32_t& outsize)
	{
	    if (m_signature.btree_size == 0) return false;

	    BTreePage page = ReadIndexPage(0);

	    bool checklastkey = false;
	    key_type lastkey = key_type();

	    while( ! page.IsLeafNode() )
	    {
		InnerNode* inner = page.GetAsInnerNode();

		CBTREEDB_CHECK(!checklastkey || !m_key_less(lastkey, inner->LastKey()),
			       "BTree corrupt (lastkey does not match).");

		int slot = BinarySearch(inner, key);

		uint32_t next = inner->childrenoffset;
		if (inner->level > 1)
		    next += slot * sizeof(InnerNode);
		else
		    next += slot * sizeof(LeafNode);

		int oldlevel = inner->level;

		if (slot < inner->slots) {
		    checklastkey = true;
		    lastkey = inner->keys[slot];
		}

		page = ReadIndexPage(next);

		CBTREEDB_CHECK(page.GetLevel() == oldlevel-1,
			       "BTree corrupt (level order mismatch).");
	    }

	    LeafNode* leaf = page.GetAsLeafNode();

	    CBTREEDB_CHECK(!checklastkey || KeyEqual(leaf->LastKey(), lastkey),
			   "BTree corrupt (lastkey in leaf does not match).");

	    int slot = BinarySearch(leaf, key);

	    if (slot >= leaf->slots || KeyUnequal(leaf->keys[slot],  key))
		return false;

	    // Return offset and size via pointers.

	    outoffset = leaf->baseoffset + leaf->offsets[slot];

	    // figure out value size of this slot: compute it from the offsets
	    CBTREEDB_CHECK(leaf->offsets[slot] <= leaf->offsets[slot+1],
			   "BTree corrupt (offsets are not ascending).");

	    outsize = leaf->offsets[slot+1] - leaf->offsets[slot];

	    return true;
	}

    public:
	/**
	 * Check if a key is in the constant database.
	 *
	 * @param key	key to lookup
	 * @return	true if found.
	 */
	bool Exists(const key_type& key)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    return FindKey(key, offset, size);
	}

	/**
	 * Find a key in the constant database. If found the corresponding
	 * value is copied into the output buffer.
	 *
	 * @param key	  key to lookup
	 * @param outvalue buffer filled with the associated value if the key is found
	 * @param maxsize maximum size of buffer
	 * @return	  true if found.
	 */
	bool Lookup(const key_type& key, void* outvalue, uint32_t maxsize)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    if (!FindKey(key, offset, size))
		return false;

	    uint32_t readsize = size;
	    if (readsize > maxsize) readsize = maxsize;

	    return ReadValueRange(offset, outvalue, readsize);
	}

	/**
	 * Find a key in the constant database. If found the coresponding value
	 * is copied into the output string buffer.
	 *
	 * @param key	  key to lookup
	 * @param outvalue string filled with the associated value if the key is found
	 * @return	  true if found.
	 */
	bool Lookup(const key_type& key, std::string& outvalue)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    if (!FindKey(key, offset, size))
		return false;

	    outvalue.resize(size);

	    return ReadValueRange(offset, const_cast<char*>(outvalue.data()), size);
	}

	/**
	 * Find a key in the constant database. If found the corresponding
	 * value is copied into the output string buffer. If the key does not
	 * exist, an empty string is returned.
	 *
	 * @param key	  key to lookup
	 * @return	  string containing the value
	 */
	std::string operator[](const key_type& key)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    if (!FindKey(key, offset, size))
		return std::string();

	    std::string outvalue;
	    outvalue.resize(size);

	    if (!ReadValueRange(offset, const_cast<char*>(outvalue.data()), size))
		return std::string();

	    return outvalue;
	}
	
    protected:
	/**
	 * Internal function to look directly into the B-tree's leaf pages and
	 * find a key by index. If found, returns the key, offset and size of
	 * the corresponding value area.
	 */
	bool FindIndex(uint32_t index, key_type& outkey, uint64_t& outoffset, uint32_t& outsize)
	{
	    if (index >= m_signature.items) return false;

	    // directly compute offset of leaf containing to the key index

	    uint32_t offset = index / LeafNodeNumKeys * BTreePageSize;
	    unsigned int slot = index % LeafNodeNumKeys;

	    BTreePage page = ReadIndexPage(m_signature.btree_firstleaf + offset);

	    CBTREEDB_CHECK(page.IsLeafNode(),
			   "BTree corrupt (expecting leaf node).");

	    LeafNode* leaf = page.GetAsLeafNode();

	    CBTREEDB_CHECK(slot < leaf->slots,
			   "BTree corrupt (index beyond range in leaf node).");

	    // copy key and offset
	    outkey = leaf->keys[slot];
	    outoffset = leaf->baseoffset + leaf->offsets[slot];

	    // figure out value size of this slot: compute it from the offsets
	    CBTREEDB_CHECK(leaf->offsets[slot] <= leaf->offsets[slot+1],
			   "BTree corrupt (offsets are not ascending).");

	    outsize = leaf->offsets[slot+1] - leaf->offsets[slot];

	    return true;
	}

    public:
	/**
	 * Returns only the key by index. Looks directly into the leaf pages.
	 *
	 * @param index		zero-based index of item to retrieve
	 * @param outkey	set to key of item
	 * @return		size of associated value if found
	 */
	uint32_t GetIndex(uint32_t index, key_type& outkey)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    if (!FindIndex(index, outkey, offset, size))
		return 0;

	    return size;
	}

	/**
	 * Return a key and associated value by index. Looks directly into the
	 * leaf pages.
	 *
	 * @param index		zero-based index of item to retrieve
	 * @param outkey	set to key of item
	 * @param outvalue	buffer to hold data of value
	 * @param maxsize	maximum size of buffer
	 * @return		size of associated value
	 */
	uint32_t GetIndex(uint32_t index, key_type& outkey, void* outvalue, uint32_t maxsize)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    if (!FindIndex(index, outkey, offset, size))
		return 0;

	    uint32_t outsize = size;
	    if (outsize > maxsize) outsize = maxsize;

	    if (!ReadValueRange(offset, outvalue, outsize))
		return 0;

	    return size;
	}

	/**
	 * Return a key and associated value by index. Looks directly into the
	 * leaf pages.
	 *
	 * @param index		zero-based index of item to retrieve
	 * @param outkey	set to key of item
	 * @param outvalue	string to hold data of value
	 * @return		size of associated value
	 */
	uint32_t GetIndex(uint32_t index, key_type& outkey, std::string& outvalue)
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    uint64_t offset;
	    uint32_t size;

	    if (!FindIndex(index, outkey, offset, size))
		return 0;

	    outvalue.resize(size);

	    if (!ReadValueRange(offset, const_cast<char*>(outvalue.data()), size))
		return 0;

	    return size;
	}

	/**
	 * Verify all aspects of the loaded database.
	 *
	 * @return	true if database is ok.
	 */
	bool Verify()
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    if (!VerifyBTree()) return false;

	    if (!VerifyBTreeChecksum()) return false;

	    if (!VerifyValueChecksum()) return false;

	    return true;
	}

	/**
	 * Verify B-tree structure in the loaded database.
	 *
	 * @return	true if database is ok.
	 */
	bool VerifyBTree()
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    if (m_signature.btree_size == 0) return true;

	    key_type minkey = key_type(), maxkey = key_type();
	    uint64_t lastoffset = 0;
	    return VerifyBTreeNode(0, &minkey, &maxkey, &lastoffset);
	}

    protected:
	/**
	 * Internal function: Recursively verify B-tree structure.
	 */
	bool VerifyBTreeNode(uint32_t offset, key_type* minkey, key_type* maxkey, uint64_t* lastoffset)
	{
	    BTreePage page = ReadIndexPage(offset);

	    if ( page.IsLeafNode() )
	    {
		LeafNode* leaf = page.GetAsLeafNode();

		if (*lastoffset != leaf->baseoffset + leaf->offsets[0]) return false;

		for(uint16_t s = 0; s < leaf->slots - 1; ++s)
		{
		    if (!m_key_less(leaf->keys[s], leaf->keys[s+1])) return false;

		    if (!(leaf->offsets[s] <= leaf->offsets[s+1])) return false;
		}

		*minkey = leaf->keys[0];
		*maxkey = leaf->keys[leaf->slots - 1];
		*lastoffset = leaf->baseoffset + leaf->offsets[leaf->slots];
	    }
	    else
	    {
		InnerNode* inner = page.GetAsInnerNode();

		for(uint16_t s = 0; s < inner->slots - 1; ++s)
		{
		    if (!m_key_less(inner->keys[s], inner->keys[s+1])) return false;
		}

		for(uint16_t s = 0; s <= inner->slots; ++s)
		{
		    uint32_t childoffset = inner->childrenoffset;

		    if (inner->level > 1)
			childoffset += s * sizeof(InnerNode);
		    else
			childoffset += s * sizeof(LeafNode);

		    key_type subminkey = key_type(), submaxkey = key_type();

		    if (!VerifyBTreeNode(childoffset, &subminkey, &submaxkey, lastoffset)) return false;

		    if (s == 0)
			*minkey = subminkey;
		    else
			if (!m_key_less(inner->keys[s-1], subminkey)) return false;

		    if (s == inner->slots)
			*maxkey = submaxkey;
		    else
			if (!KeyEqual(inner->keys[s], submaxkey)) return false;
		}
	    }

	    return true;
	}

    public:
	/**
	 * Verify the SHA256 checksum of the B-tree pages in the loaded
	 * database.
	 *
	 * @return	true if database is ok.
	 */
	bool VerifyBTreeChecksum()
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    SHA256 sha;

	    for(uint32_t offset = 0; offset < m_signature.btree_size; offset += BTreePageSize)
	    {
		BTreePage page = ReadIndexPage(offset);

		sha.update(page.GetBuffer(), BTreePageSize);
	    }

	    return ( sha.final_equals(m_signature.btree_sha256) );
	}

	/**
	 * Verify the SHA256 checksum of value data area in the loaded
	 * database.
	 *
	 * @return	true if database is ok.
	 */
	bool VerifyValueChecksum()
	{
	    CBTREEDB_CHECK(m_istream, "No database loaded.");

	    SHA256 sha;

	    char buffer[64*1024];

	    for(uint64_t offset = 0; offset < m_signature.value_size; offset += sizeof(buffer))
	    {
		uint64_t remsize = std::min<uint64_t>(sizeof(buffer), m_signature.value_size - offset);

		if (!ReadValueRange(offset, buffer, remsize))
		    return false;

		sha.update(buffer, remsize);
	    }

	    return( sha.final_equals(m_signature.value_sha256) );
	}
    };

public:
    /**
     * @brief Class used to read constant B-tree database files.
     *
     * This is a reference counted front-end to ReaderImpl.
     *
     * Refer to \ref sec_architecture and \ref sec_example on how to use this class.
     */
    class Reader
    {
    protected:

	/// pointer to implementation class.
	ReaderImpl*	m_impl;

    public:
	/// Create new reader, which is initially set to closed state.
	Reader(const key_compare& key_less=key_compare())
	    : m_impl(new ReaderImpl(key_less))
	{
	    m_impl->RefInc();
	}

	/// Copy Constructor: increment reference counter on base object.
	Reader(const Reader& rd)
	    : m_impl(rd.m_impl)
	{
	    m_impl->RefInc();
	}

	/// Destructor: decrement reference counter on buffer and possibly
	/// deallocate it.
	~Reader()
	{
	    if (m_impl->RefDec() == 0)
		delete m_impl;
	}

	/// Assignment Operator: increment reference counter on base object.
	Reader& operator=(const Reader& rd)
	{
	    if (this != &rd)
	    {
		if (m_impl->RefDec() == 0)
		    delete m_impl;

		m_impl = rd.m_impl;
		m_impl->RefInc();
	    }

	    return *this;
	}

	/**
	 * Change the database signature (first 8 bytes) from 'cbtreedb' to a
	 * custom string. The signature is always 8 bytes long. Longer strings
	 * are truncated, shorter ones padded with nulls.
	 */
	void SetSignature(const char* newsignature)
	{
	    return m_impl->SetSignature(newsignature);
	}

	/**
	 * Attempt to open a cbtreedb database file. Reads and verifies the
	 * signature and initializes the reader. Note that this function does
	 * not through an exception if the file could not be loaded! The
	 * istream object must exist as long as the Reader is used.
	 *
	 * @param file		database file input stream to attach.
	 * @param errortext	in case of error, set to an informative text.
	 * @return		true if loaded and verified correctly.
	 */
	bool Open(std::istream& file, std::string* errortext = NULL)
	{
	    return m_impl->Open(file, errortext);
	}

	/**
	 * Close the opened database.
	 */
	void Close()
	{
	    return m_impl->Close();
	}

	/// Change the currently used page cache object
	void SetPageCache(PageCache* newpagecache)
	{
	    return m_impl->SetPageCache(newpagecache);
	}

	/**
	 * Returns the number of items in the loaded database.
	 */
	uint32_t Size() const
	{
	    return m_impl->Size();
	}

	/**
	 * Returns a const reference to the signature page of the currently
	 * loaded database.
	 */
	const SignaturePage& GetSignature() const
	{
	    return m_impl->GetSignature();
	}

	/**
	 * Check if a key is in the constant database.
	 *
	 * @param key	key to lookup
	 * @return	true if found.
	 */
	bool Exists(const key_type& key)
	{
	    return m_impl->Exists(key);
	}

	/**
	 * Find a key in the constant database. If found the corresponding
	 * value is copied into the output buffer.
	 *
	 * @param key	  key to lookup
	 * @param outvalue buffer filled with the associated value if the key is found
	 * @param maxsize maximum size of buffer
	 * @return	  true if found.
	 */
	bool Lookup(const key_type& key, void* outvalue, uint32_t maxsize)
	{
	    return m_impl->Lookup(key, outvalue, maxsize);
	}

	/**
	 * Find a key in the constant database. If found the coresponding value
	 * is copied into the output string buffer.
	 *
	 * @param key	  key to lookup
	 * @param outvalue string filled with the associated value if the key is found
	 * @return	  true if found.
	 */
	bool Lookup(const key_type& key, std::string& outvalue)
	{
	    return m_impl->Lookup(key, outvalue);
	}

	/**
	 * Find a key in the constant database. If found the corresponding
	 * value is copied into the output string buffer. If the key does not
	 * exist, an empty string is returned.
	 *
	 * @param key	  key to lookup
	 * @return	  string containing the value
	 */
	std::string operator[](const key_type& key)
	{
	    return (*m_impl)[key];
	}

	/**
	 * Returns only the key by index. Looks directly into the leaf pages.
	 *
	 * @param index		zero-based index of item to retrieve
	 * @param outkey	set to key of item
	 * @return		size of key's data
	 */
	uint32_t GetIndex(uint32_t index, key_type& outkey)
	{
	    return m_impl->GetIndex(index, outkey);
	}

	/**
	 * Return a key and associated value by index. Looks directly into the
	 * leaf pages.
	 *
	 * @param index		zero-based index of item to retrieve
	 * @param outkey	set to key of item
	 * @param outvalue	buffer to hold data of value
	 * @param maxsize	maximum size of buffer
	 * @return		size of associated value
	 */
	uint32_t GetIndex(uint32_t index, key_type& outkey, void* outvalue, uint32_t maxsize)
	{
	    return m_impl->GetIndex(index, outkey, outvalue, maxsize);
	}

	/**
	 * Return a key and associated value by index. Looks directly into the
	 * leaf pages.
	 *
	 * @param index		zero-based index of item to retrieve
	 * @param outkey	set to key of item
	 * @param outvalue	string to hold data of value
	 * @return		size of associated value
	 */
	uint32_t GetIndex(uint32_t index, key_type& outkey, std::string& outvalue)
	{
	    return m_impl->GetIndex(index, outkey, outvalue);
	}

	/**
	 * Verify all aspects of the loaded database.
	 *
	 * @return	true if database is ok.
	 */
	bool Verify()
	{
	    return m_impl->Verify();
	}

	/**
	 * Verify B-tree structure in the loaded database.
	 *
	 * @return	true if database is ok.
	 */
	bool VerifyBTree()
	{
	    return m_impl->VerifyBTree();
	}

	/**
	 * Verify the SHA256 checksum of the B-tree pages in the loaded
	 * database.
	 *
	 * @return	true if database is ok.
	 */
	bool VerifyBTreeChecksum()
	{
	    return m_impl->VerifyBTreeChecksum();
	}

	/**
	 * Verify the SHA256 checksum of value data area in the loaded
	 * database.
	 *
	 * @return	true if database is ok.
	 */
	bool VerifyValueChecksum()
	{
	    return m_impl->VerifyValueChecksum();
	}
    };

protected:

    /**
     * @brief BTreeBuilder is used to construct an index very similar to a
     * B-tree from an ordered sequence.
     *
     * The tree builder class is fed with an ordered sequence of keys together
     * with their value size and offset. The information is stored into the
     * nodes of the tree in memory.
     */
    class BTreeBuilder
    {
    protected:

	/// key comparison functional
	key_compare	m_key_less;

	/// total number of items stored in the tree
	unsigned int	m_size;

	/// leaves of the B-tree
	std::vector<LeafNode> m_leaves;

	/// typedef of each inner level of the B-tree
	typedef std::vector<InnerNode> innerlevel_type;

	/// vector holding a list of b-tree inner levels. Each level contains a
	/// list of inner nodes.
	std::vector<innerlevel_type> m_inners;

    public:
	/// Construct a new empty tree builder.
	BTreeBuilder(const key_compare& key_less)
	    : m_key_less(key_less), m_size(0)
	{
	}

    protected:
	/// Add a key value in an inner node at given level. Called by Add when
	/// a leaf node overflows.
	void AddInner(uint16_t level, const key_type& key)
	{
	    if (m_inners.size() < level)
	    {
		CBTREEDB_ASSERT(m_inners.size()+1 == level);

		// Create vector for this level
		m_inners.push_back(innerlevel_type());
	    }

	    if (m_inners[level-1].size() == 0)
	    {
		// Create first inner node on this level
		m_inners[level-1].push_back(InnerNode(level));
	    }

	    InnerNode* inner = &m_inners[level-1].back();

	    CBTREEDB_ASSERT(inner->slots == 0 || m_key_less(inner->LastKey(), key));

	    if (inner->IsFull())
	    {
		CBTREEDB_ASSERT(m_key_less(inner->LastKey(), key));

		// Put last key of leaf key into inner node(s) of higher level
		AddInner(inner->level + 1, key);

		// Create new inner node
		m_inners[level-1].push_back(InnerNode(level));
		inner = &m_inners[level-1].back();
	    }
	    else
	    {
		// Append Key
		inner->keys[inner->slots++] = key;
	    }
	}

    public:
	/**
	 * Insert a new key into the tree together with (offset,size) of the
	 * associated data value. The keys must be delivered to this function
	 * in ascending order!
	 */
	void Add(const key_type& key, uint64_t offset, uint32_t size)
	{
	    if (m_leaves.size() == 0) {
		// create first leaf node
		m_leaves.push_back(LeafNode());
	    }

	    LeafNode* leaf = &m_leaves.back();

	    if (leaf->slots > 0) {
		CBTREEDB_ASSERT(m_key_less(leaf->LastKey(), key));
	    }

	    if (leaf->IsFull())
	    {
		// put last key into inner node(s)
		AddInner(1, leaf->LastKey());

		// create new leaf
		m_leaves.push_back(LeafNode());
		leaf = &m_leaves.back();
		leaf->baseoffset = offset;
	    }

	    // append key + value items relative offset
	    leaf->keys[leaf->slots] = key;

	    CBTREEDB_ASSERT(offset >= leaf->baseoffset);
	    leaf->offsets[leaf->slots] = offset - leaf->baseoffset;
	    leaf->offsets[leaf->slots+1] = leaf->offsets[leaf->slots] + size;

	    ++leaf->slots;
	    ++m_size;
	}

	/// Returns the number of items added to the tree.
	unsigned int Size() const
	{
	    return m_size;
	}

	/// Return highest key currently inserted in the tree
	const key_type& GetLastKey() const
	{
	    CBTREEDB_CHECK(m_size > 0, "No keys inserted in the tree yet");

	    return m_leaves.back().LastKey();
	}

	/// Return key previously inserted at given index
	void GetIndex(unsigned int index, key_type& outkey, uint32_t& outsize) const
	{
	    CBTREEDB_CHECK(index < m_size, "Attempting to retrieve out of bounds index.");

	    unsigned int leafnum = index / LeafNodeNumKeys;
	    unsigned int slot = index % LeafNodeNumKeys;

	    CBTREEDB_ASSERT(leafnum < m_leaves.size());

	    const LeafNode* leaf = &m_leaves[leafnum];

	    CBTREEDB_ASSERT(slot < leaf->slots);

	    outkey = leaf->keys[slot];
	    outsize = leaf->offsets[slot+1] - leaf->offsets[slot];
	}

#if 0 // extra debug code for printing the tree

	/**
	 * Debugging function which prints out all keys in the currently
	 * constructed B-tree.
	 */
	void Print(std::ostream& os) const
	{
	    os << "Leaves:" << std::endl;
	    for (unsigned int i = 0; i < m_leaves.size(); ++i)
	    {
		os << i << ":";
		for (unsigned int j = 0; j < m_leaves[i].slots; ++j)
		{
		    os << " " << m_leaves[i].keys[j];
		}
		os << std::endl;
	    }

	    for (unsigned int l = 0; l < m_inners.size(); ++l)
	    {
		os << "Level " << (l+1) << std::endl;

		for (unsigned int i = 0; i < m_inners[l].size(); ++i)
		{
		    os << i << ":";
		    for (unsigned int j = 0; j < m_inners[l][i].slots; ++j)
		    {
			os << " " << m_inners[l][i].keys[j];
		    }
		    os << std::endl;
		}
	    }
	}

#endif // extra debug code for printing the tree

	/**
	 * Write function which outputs the constructed B-tree to a stream. The
	 * levels are outputted from root to leaf nodes in order. Updates the
	 * given signature page with B-tree information.
	 */
	void Write(std::ostream& os, SignaturePage& signature)
	{
	    signature.btree_pagesize = BTreePageSize;
	    signature.btree_levels = m_inners.size() + 1;
	    signature.btree_leaves = m_leaves.size();

	    // Fill in childrenoffset field by precomputing the offsets.
	    {
		// start with offset after the root (inner) node.
		uint32_t offset = sizeof(InnerNode);

		for (int l = m_inners.size()-1; l >= 0; --l)
		{
		    for (unsigned int i = 0; i < m_inners[l].size(); ++i)
		    {
			InnerNode& inner = m_inners[l][i];

			inner.childrenoffset = offset;

			// add all children node sizes to offset.
			offset += (inner.slots + 1) * sizeof(InnerNode);
		    }
		}
	    }

	    // Write out inner nodes

	    uint64_t writesize = 0;
	    SHA256 sha;

	    for (int l = m_inners.size()-1; l >= 0; --l)
	    {
		for (unsigned int i = 0; i < m_inners[l].size(); ++i)
		{
		    os.write(reinterpret_cast<char*>(&m_inners[l][i]), sizeof(m_inners[l][i]));
		    CBTREEDB_CHECK(os.good(), "Error writing B-tree inner node page to output stream.");

		    sha.update(&m_inners[l][i], sizeof(m_inners[l][i]));

		    writesize += sizeof(m_inners[l][i]);
		}
	    }

	    // Write out leaf nodes

	    signature.btree_firstleaf = writesize;

	    for (unsigned int i = 0; i < m_leaves.size(); ++i)
	    {
		os.write(reinterpret_cast<char*>(&m_leaves[i]), sizeof(m_leaves[i]));
		CBTREEDB_CHECK(os.good(), "Error writing B-tree leaf node page to output stream.");

		sha.update(&m_leaves[i], sizeof(m_leaves[i]));

		writesize += sizeof(m_leaves[i]);
	    }

	    sha.final(signature.btree_sha256);
	    signature.btree_size = writesize;
	}
    };

public:
    /**
     * @brief Writer is used to construct an constant B-tree database from an
     * unsorted input sequence.
     *
     * The writer class is fed with a possibly unordered sequence of keys
     * together with their data. The complete data is buffered (and sorted) by
     * the class! This means it will use a lot of virtual memory, so make sure
     * your swap is large enough or use WriterSequential.
     */
    class Writer
    {
    protected:
	/// Typedef key -> data mapping
	typedef std::map<key_type, std::string, key_compare> datamap_type;

	/// STL map to store all key -> values.
	datamap_type	m_datamap;

	/// key comparison functional
	key_compare	m_key_less;

	/// Signature characters to begin file with.
	char		m_signaturestr[8];

    public:
	/// Constructor
	Writer(const key_compare& key_less=key_compare())
	    : m_datamap(key_less),
	      m_key_less(key_less)
	{
	    memcpy(m_signaturestr, "cbtreedb", 8);
	}

	/// Add a new key -> values mapping to the database.
	void Add(const key_type& key, const void* data, size_t size)
	{
	    m_datamap.insert( typename datamap_type::value_type(key, std::string(reinterpret_cast<const char*>(data), size)) );
	}

	/// Add a new key -> values mapping to the database.
	void Add(const key_type& key, const std::string& data)
	{
	    Add(key, data.data(), data.size());
	}

	/// Return number of items inserted into mapping
	size_t Size() const
	{
	    return m_datamap.size();
	}

	/**
	 * Change the database signature from 'cbtreedb' to a custom
	 * string. The signature is always 8 bytes long. Longer strings are
	 * truncated, shorter ones padded with nulls.
	 */
	void SetSignature(const char* newsignature)
	{
	    unsigned int i = 0;
	    for(; i < 8 && newsignature[i]; ++i)
		m_signaturestr[i] = newsignature[i];

	    for(; i < 8; ++i)
		m_signaturestr[i] = 0;
	}

	/// Write the complete database out to a file. Because the stream must
	/// be seekable, a simple ostream will not suffice.
	void Write(std::ostream& os) const
	{
	    os.seekp(0, std::ios::beg);

	    // Write zeroed signature block to be overwritten when the file is
	    // finialized.

	    SignaturePage signature;
	    memset(&signature, 0, sizeof(signature));
	    os.write(reinterpret_cast<char*>(&signature), sizeof(signature));

	    char signature_padding[SignaturePageSize - sizeof(SignaturePage)];
	    memset(signature_padding, 0, SignaturePageSize - sizeof(SignaturePage));
	    os.write(signature_padding, SignaturePageSize - sizeof(SignaturePage));

	    CBTREEDB_CHECK(os.good(), "Error writing signature block out output stream.");

	    // Prepare signature for data

	    memcpy(signature.signature, m_signaturestr, 8);
	    signature.version = 0x00010000;
	    signature.app_version_id = AppVersionId;
	    signature.items = m_datamap.size();
	    signature.key_size = sizeof(key_type);

	    // Construct a and write a constant B-Tree

	    BTreeBuilder btree(m_key_less);
	    uint64_t dataoffset = 0;

	    for (typename datamap_type::const_iterator di = m_datamap.begin();
		 di != m_datamap.end(); ++di)
	    {
		btree.Add(di->first, dataoffset, di->second.size());
		dataoffset += di->second.size();
	    }

	    signature.btree_offset = BTreePageSize;
	    btree.Write(os, signature);

	    CBTREEDB_CHECK(os.good(), "Error writing B-tree pages to output stream.");
	    CBTREEDB_ASSERT(os.tellp() == std::ostream::pos_type(SignaturePageSize + signature.btree_size));

	    // Write all value blobs to file

	    SHA256 sha;

	    for (typename datamap_type::const_iterator di = m_datamap.begin();
		 di != m_datamap.end(); ++di)
	    {
		os.write(di->second.data(), di->second.size());
		CBTREEDB_CHECK(os.good(), "Error writing data block to output stream.");

		sha.update(di->second.data(), di->second.size());
	    }

	    CBTREEDB_ASSERT(os.tellp() == std::ostream::pos_type(SignaturePageSize + signature.btree_size + dataoffset));

	    // Fill in signature page

	    signature.value_offset = SignaturePageSize + signature.btree_size;
	    signature.value_size = dataoffset;
	    sha.final(signature.value_sha256);

	    // Calculate header checksum

	    signature.header_crc32 = CRC32::digest(reinterpret_cast<char*>(&signature)+16, sizeof(signature)-16);

	    os.seekp(0, std::ios::beg);
	    CBTREEDB_CHECK(os.good(), "Error seeking back to signature page in output stream.");
	    CBTREEDB_ASSERT(os.tellp() == std::ostream::pos_type(0));

	    os.write(reinterpret_cast<char*>(&signature), sizeof(signature));
	    CBTREEDB_CHECK(os.good(), "Error writing signature page to output stream.");
	}
    };

public:
    /**
     * @brief WriterSequential is used to construct a constant B-tree database
     * from an _ordered_ input sequence.
     *
     * The writer class is fed in two phases. In phase one the ordered sequence
     * of keys together with their value data size (without contents) is
     * delivered to the class via the Add() function. Phase two is started by
     * calling WriteHeader() followed by a sequence to WriteValue() calls for
     * each of the predeclared key-value pairs. The value data is written
     * directly to the file and not buffered. The write loop is terminated by
     * WriteFinalize(), which finalizes the database file.
     */
    class WriterSequential
    {
    protected:
	/// key comparison functional
	key_compare	m_key_less;

	/// phase 1: b-tree object built from sequential predeclared sequence
	BTreeBuilder	m_btree;

	/// phase 1: value data offset counter for predeclared sequence
	uint64_t	m_dataoffset;

	/// signature characters to begin file with
	char		m_signaturestr[8];

	/// signature page of current written file
	SignaturePage	m_signature;

	/// phase 2: output stream
	std::ostream*	m_ostream;

	/// phase 2: current position in array
	uint32_t	m_currpos;

	/// phase 2: current offset in output stream
	uint64_t	m_curroffset;

	/// phase 2: running digest of the value area
	SHA256		m_datasha;

    public:
	/// Constructor
	WriterSequential(const key_compare& key_less=key_compare())
	    : m_key_less(key_less),
	      m_btree(key_less),
	      m_dataoffset(0),
	      m_ostream(NULL),
	      m_currpos(-1)
	{
	    memcpy(m_signaturestr, "cbtreedb", 8);
	}

	/// Add a new key -> value size mapping to the database. The keys must
	/// be added in ascending order.
	void Add(const key_type& key, uint32_t size)
	{
	    CBTREEDB_CHECK(m_btree.Size() == 0 || m_key_less(m_btree.GetLastKey(), key),
			   "Key sequence for Add() must be ascending.");
	    CBTREEDB_CHECK(m_ostream == NULL,
			   "Cannot declare keys after starting phase 2.");

	    m_btree.Add(key, m_dataoffset, size);
	    m_dataoffset += size;
	}

	/// Return number of pairs inserted into mapping
	size_t Size() const
	{
	    return m_btree.Size();
	}

	/**
	 * Change the database signature from 'cbtreedb' to a custom
	 * string. The signature is always 8 bytes long. Longer strings are
	 * truncated, shorter ones padded with nulls.
	 */
	void SetSignature(const char* newsignature)
	{
	    unsigned int i = 0;
	    for(; i < 8 && newsignature[i]; ++i)
		m_signaturestr[i] = newsignature[i];

	    for(; i < 8; ++i)
		m_signaturestr[i] = 0;
	}

	/// Write header and b-tree to file stream. Starts Phase 2.
	void WriteHeader(std::ostream& os)
	{
	    CBTREEDB_CHECK(m_ostream == NULL,
			   "Cannot write header again in phase 2.");

	    os.seekp(0, std::ios::beg);

	    // write zeroed signature page to be overwritten when the file is
	    // finialized.
	    memset(&m_signature, 0, sizeof(m_signature));
	    os.write(reinterpret_cast<char*>(&m_signature), sizeof(m_signature));

	    char signature_padding[SignaturePageSize - sizeof(SignaturePage)];
	    memset(signature_padding, 0, SignaturePageSize - sizeof(SignaturePage));
	    os.write(signature_padding, SignaturePageSize - sizeof(SignaturePage));

	    CBTREEDB_CHECK(os.good(), "Error writing signature page to output stream.");

	    // prepare signature for data

	    memcpy(m_signature.signature, m_signaturestr, 8);
	    m_signature.version = 0x00010000;
	    m_signature.app_version_id = AppVersionId;
	    m_signature.btree_offset = SignaturePageSize;
	    m_signature.items = m_btree.Size();
	    m_signature.key_size = sizeof(key_type);
	    m_signature.value_size = m_dataoffset;

	    // write constant B-tree

	    m_btree.Write(os, m_signature);
	    CBTREEDB_CHECK(os.good(), "Error writing B-tree pages to output stream.");
	    CBTREEDB_ASSERT(os.tellp() == std::ostream::pos_type(SignaturePageSize + m_signature.btree_size));

	    // prepare for writing value area

	    m_ostream = &os;
	    m_currpos = 0;
	    m_curroffset = 0;
	    m_datasha.clear();
	}

	/// Sequentially write value blobs to file. The key-value sequence must
	/// match the pre-declared sequence.
	void WriteValue(const key_type& key, const void* data, uint32_t size)
	{
	    CBTREEDB_CHECK(m_ostream != NULL,
			   "Cannot write data, because phase 2 was not started.");

	    CBTREEDB_CHECK(m_currpos < m_btree.Size(),
			   "Invalid key in WriteData() beyond end of predeclaration.");

	    CBTREEDB_CHECK(m_ostream->tellp() == std::ostream::pos_type(SignaturePageSize + m_signature.btree_size + m_curroffset),
			   "Output stream data position is incorrect.");

	    key_type expectedkey;
	    uint32_t expectedsize;

	    m_btree.GetIndex(m_currpos, expectedkey, expectedsize);

	    CBTREEDB_CHECK(!m_key_less(key, expectedkey) && !m_key_less(expectedkey, key), // test equality
			   "Key in WriteData() mismatches predeclared sequence.");

	    CBTREEDB_CHECK(size == expectedsize,
			   "Value data size in WriteData() mismatches predeclared sequence.");

	    m_ostream->write(reinterpret_cast<const char*>(data), size);
	    CBTREEDB_CHECK(m_ostream->good(), "Error writing data blocks to output stream.");

	    m_datasha.update(data, size);

	    ++m_currpos;
	    m_curroffset += size;
	}

	/// Sequentially write value blobs to file. The key-value sequence must
	/// match the pre-declared sequence.
	void WriteValue(const key_type& key, const std::string& data)
	{
	    return WriteValue(key, data.data(), data.size());
	}

	/// Finalize database file
	void WriteFinalize()
	{
	    CBTREEDB_CHECK(m_ostream != NULL,
			   "Cannot write data, because phase 2 was not started.");

	    CBTREEDB_CHECK(m_currpos == m_btree.Size(),
			   "WriteFinalize() called before end of predeclared sequence.");

	    CBTREEDB_CHECK(m_ostream->tellp() == std::ostream::pos_type(SignaturePageSize + m_signature.btree_size + m_signature.value_size),
			   "Output stream data position is incorrect.");

	    // Fill in signature page

	    m_signature.value_offset = SignaturePageSize + m_signature.btree_size;
	    m_datasha.final(m_signature.value_sha256);

	    // Calculate header checksum

	    m_signature.header_crc32 = CRC32::digest(reinterpret_cast<char*>(&m_signature)+16, sizeof(m_signature)-16);

	    m_ostream->seekp(0, std::ios::beg);
	    CBTREEDB_CHECK(m_ostream->good(), "Error seeking back to signature page in output stream.");

	    m_ostream->write(reinterpret_cast<char*>(&m_signature), sizeof(m_signature));
	    CBTREEDB_CHECK(m_ostream->good(), "Error writing signature page to output stream.");

	    m_ostream->flush();
	    m_ostream = NULL;
	}
    };
};

} // namespace stx

#endif // _STX_CBTREEDB_H_
