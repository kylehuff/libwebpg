PROJECT:=webpg
PROJECT_ROOT:=$(CURDIR)

CC = gcc

ifeq ($(CC),gcc)
	LBITS := $(shell getconf LONG_BIT)
endif

BINEXT=
SOEXT=.so

ifndef PLATFORM
  ifeq ($(shell uname),Darwin)
    PLATFORM=macosx
    DISTDIR=Darwin_x86_64-gcc
    SOEXT=.dylib
    CFLAGS += -static-libgcc
  else ifeq ($(shell uname),FreeBSD)
    PLATFORM=bsd
	  ifeq ($(LBITS),64)
		  DISTDIR=BSD_x86_64-gcc
	  else
		  DISTDIR=BSD_x86-gcc
		endif
  else ifeq ($(shell uname),NetBSD)
    PLATFORM=bsd
	  ifeq ($(LBITS),64)
		  DISTDIR=BSD_x86_64-gcc
	  else
		  DISTDIR=BSD_x86-gcc
		endif
  else ifeq ($(shell uname),OpenBSD)
    PLATFORM=bsd
	  ifeq ($(LBITS),64)
		  DISTDIR=BSD_x86_64-gcc
	  else
		  DISTDIR=BSD_x86-gcc
		endif
  else ifeq ($(shell uname),DragonFly)
    PLATFORM=bsd
	  ifeq ($(LBITS),64)
		  DISTDIR=BSD_x86_64-gcc
	  else
		  DISTDIR=BSD_x86-gcc
		endif
  else ifeq ($(shell uname -o),Msys)
    PLATFORM=mingw
    BINEXT=.exe
    SOEXT=.dll
	  ifeq ($(TARGET_CPU),x86_64)
		  DISTDIR=WINNT_x86_64-msvc
	  else
		  DISTDIR=WINNT_x86-msvc
	  endif
  else ifeq ($(shell uname -o),Cygwin)
    PLATFORM=cygwin
    BINEXT=.exe
    SOEXT=.dll
	  ifeq ($(TARGET_CPU),x86_64)
		  DISTDIR=WINNT_x86_64-msvc
	  else
		  DISTDIR=WINNT_x86-msvc
		endif
  else ifeq ($(shell uname -o),GNU/Linux)
    PLATFORM=linux
    LDFLAGS += -ldl
	  ifeq ($(LBITS),64)
		  DISTDIR=Linux_x86_64-gcc
	  else
		  DISTDIR=Linux_x86-gcc
		endif
  else
    PLATFORM=unix
	  ifeq ($(LBITS),64)
		  DISTDIR=Linux_x86_64-gcc
	  else
		  DISTDIR=Linux_x86-gcc
		endif
  endif
endif

BINDIR=$(CURDIR)/build/bin
LIBDIR=$(CURDIR)/build/lib

LDFLAGS:=$(PROJECT_ROOT)/libs/libgpgme/$(DISTDIR)/libgpgme.a \
  $(PROJECT_ROOT)/libs/libgpg-error/$(DISTDIR)/libgpg-error.a \
  $(PROJECT_ROOT)/libs/libassuan/$(DISTDIR)/libassuan.a \
  $(PROJECT_ROOT)/libs/jsoncpp/$(DISTDIR)/libjsoncpp.a

CFLAGS += -I $(PROJECT_ROOT)/libs/boost/include \
  -I $(PROJECT_ROOT)/libs/libgpgme/${DISTDIR}/include \
  -I $(PROJECT_ROOT)/libs/libgpg-error/${DISTDIR}/include \
  -D_FILE_OFFSET_BITS=64 -g -Wall

ifeq ($(CC),gcc)
	LDFLAGS += -DDEBUG -lstdc++
else
	LDFLAGS += -DDEBUG -lgdi32 -lstdc++ -ljsoncpp
endif

ifeq ($(LBITS),64)
  CFLAGS += -fPIC
endif

webpg : webpg.cc
	@set -e; echo ${PLATFORM}; if [ ! -d "${BINDIR}/${DISTDIR}" ]; then \
		mkdir -vp ${BINDIR}/${DISTDIR}; \
	fi
	@set -e; if [ ! -d "${LIBDIR}/${DISTDIR}" ]; then \
		mkdir -vp ${LIBDIR}/${DISTDIR}; \
	fi
	$(CC) $(CFLAGS) -pthread -o ${BINDIR}/${DISTDIR}/${PROJECT}${BINEXT} webpg.cc $(LDFLAGS)
	$(CC) $(CFLAGS) -DH_WEBPGLIB -pthread -shared -o ${LIBDIR}/${DISTDIR}/lib${PROJECT}${SOEXT} webpg.cc $(LDFLAGS)

clean:
	@set -e; echo "cleaning build directory...";
	@set -e; for d in $(BINDIR)/*; do \
		for f in $$d/*; do \
			if [ -e "$$f" ]; then \
				rm -v $$f; \
			fi; \
			rm -r $$d; \
		done; \
	done
	@set -e; for d in $(LIBDIR)/*; do \
		for f in $$d/*; do \
			if [ -e "$$f" ]; then \
				rm -v $$f; \
			fi; \
			rm -r $$d; \
		done; \
	done
	@set -e; echo "done.";
