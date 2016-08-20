include build/rules.mk

SUBDIRS = 	kva-tool	\
		mmsearch	\
		mmsearch/test	\
		kernel-rk	\

all: subdirs

clean:
	@for dir in $(SUBDIRS) ; do \
        if [ -d $$dir ]; then ( cd $$dir ; make clean ) ; fi \
    done

include build/common.mk










