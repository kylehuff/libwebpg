PROJECT:=webpg
PROJECT_ROOT:=$(CURDIR)

LBITS := $(shell getconf LONG_BIT)
SHELL := sh

BINEXT=
SOEXT=.so

ifndef PLATFORM
  ifeq ($(shell uname),Darwin)
    PLATFORM=macosx
    DISTDIR=Darwin_x86_64-gcc
    SOEXT=.dylib
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
    ifeq ($(LBITS),64)
      DISTDIR=Linux_x86_64-gcc
    else
      DISTDIR=Linux_x86-gcc
    endif
    ifeq ($(shell uname -m | grep -oP 'armv[\d][\w]' | grep -oP 'arm'),arm)
      DISTDIR=Linux_armv$(shell uname -m | grep -oP 'armv[\d][\w]' | grep -oP '[\d]')-gcc
    endif
  else
    PLATFORM=unix
    ifeq ($(LBITS),64)
      DISTDIR=Linux_x86_64-gcc
    else
      DISTDIR=Linux_x86-gcc
    endif
    ifeq ($(shell uname -m | grep -oP 'armv[\d][\w]' | grep -oP 'arm'),arm)
      DISTDIR=Linux_armv$(shell uname -m | grep -oP 'armv[\d][\w]' | grep -oP '[\d]')-gcc
    endif
  endif
endif

BINDIR=$(CURDIR)/build/bin
LIBDIR=$(CURDIR)/build/lib

all : bin lib

bin:
	@if [ ! -d "${BINDIR}/${DISTDIR}" ]; then \
		mkdir -vp "${BINDIR}/${DISTDIR}"; \
	fi
	$(CXX) $(shell ${PROJECT_ROOT}/config.sh ${CXX} CXXFLAGS STATIC) -o "${BINDIR}/${DISTDIR}/${PROJECT}${BINEXT}" webpg.cc $(shell ${PROJECT_ROOT}/config.sh ${CXX} LDFLAGS STATIC)

lib:
	@set -e; if [ ! -d "${LIBDIR}/${DISTDIR}" ]; then \
		mkdir -vp "${LIBDIR}/${DISTDIR}"; \
	fi
	$(CXX) $(shell ${PROJECT_ROOT}/config.sh ${CXX} CXXFLAGS SHARED) -DH_LIBWEBPG -shared -o "${LIBDIR}/${DISTDIR}/lib${PROJECT}${SOEXT}" webpg.cc $(shell ${PROJECT_ROOT}/config.sh ${CXX} LDFLAGS SHARED)

clean:
	@set -e; echo "cleaning build directory...";
	@set -e; rm -vrf $(BINDIR);
	@set -e; echo "done.";
