# $Id$

check_PROGRAMS = test_crc32 test_sha256 test_pagecache test_instantiate test_writeread test_format

TESTS = test_crc32 test_sha256 test_pagecache test_instantiate test_writeread  test_format

test_crc32_SOURCES = test_crc32.cc

test_sha256_SOURCES = test_sha256.cc

test_pagecache_SOURCES = test_pagecache.cc

test_instantiate_SOURCES = test_instantiate.cc

test_writeread_SOURCES = test_writeread.cc

test_format_SOURCES = test_format.cc

AM_CXXFLAGS = -g -W -Wall -Wold-style-cast -I$(top_srcdir)/include -DAM_TOP_SRCDIR=\"$(top_srcdir)\"

EXTRA_DIST = test_format1.db test_format2.db