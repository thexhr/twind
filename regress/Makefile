BASEDIR=	/var/twind/localhost/tests

testdirs:
	mkdir -p $(BASEDIR)
	mkdir -p $(BASEDIR)/subdir

testfiles:
	echo "1e6b1c887c59a315edb7eb9a315fc84c" > $(BASEDIR)/index.gmi
	echo "1e6b1c887c59a315edb7eb9a315fc84c" > $(BASEDIR)/subdir/index.gmi
	echo "1e6b1c887c59a315edb7eb9a315fc84c" > $(BASEDIR)/subdir/test.gmi
	ln -s index.gmi $(BASEDIR)/link.gmi

all: testdir testfiles
