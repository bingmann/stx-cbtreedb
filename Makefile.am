# $Id$

SUBDIRS = . testsuite tools

include_HEADERS = include/stx-cbtreedb.h

EXTRA_DIST = Doxyfile mainpage.dox doxygen-html

if GCOV

clean-local:
	find -name "*.da" -o -name "*.gcov" -o -name "*.gcda" -o -name "*.gcno" | xargs rm || true

run-gcov: clean-gcov
	mkdir -p coverage/
	lcov --directory . --zerocounters
	-$(MAKE) check
	lcov --directory . --capture --output-file coverage/all.info
	lcov -e coverage/all.info "/tdata/*" -o coverage/testsuite.info
	genhtml -o coverage --num-spaces 8 coverage/testsuite.info --title "STX CBTreeDB Testsuite" --prefix `pwd`

clean-gcov:
	find -name "*.gcda" | xargs rm || true

endif
