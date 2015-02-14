PROJECT:=webpg
PROJECT_ROOT:=$(CURDIR)

ifeq ($(shell type getconf 2>&1 | awk -v pat="not found" 'BEGIN {FS="\n"; RS="";OFS="\n";} $$0 ~ pat { print "NOT_FOUND" };'),NOT_FOUND)
  LBITS := $(shell file /bin/cp | awk -v pat="32" 'BEGIN {FS="\n"; RS="";OFS="\n";} $$0 ~ pat { print pat };')
else
  LBITS := $(shell getconf LONG_BIT)
endif
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
	$(eval FLAGS="$(shell '${PROJECT_ROOT}/config.sh' ${CXX} STATIC)")
	$(eval CXXFLAGS=$(shell echo ${FLAGS} | awk 'BEGIN {FS="\n"; RS="";OFS="\n";} END { split($$0, N, ","); print substr(N[1], index(N[1], "=")+1) }'))
	$(eval LDFLAGS=$(shell echo ${FLAGS} | awk 'BEGIN {FS="\n"; RS="";OFS="\n";} END { split($$0, N, ","); print substr(N[2], index(N[2], "=")+1) }'))
	$(CXX) ${CXXFLAGS} -o "${BINDIR}/${DISTDIR}/${PROJECT}${BINEXT}" webpg.cc ${LDFLAGS}

lib:
	@set -e; if [ ! -d "${LIBDIR}/${DISTDIR}" ]; then \
		mkdir -vp "${LIBDIR}/${DISTDIR}"; \
	fi
	$(eval FLAGS="$(shell '${PROJECT_ROOT}/config.sh' ${CXX} SHARED)")
	$(eval CXXFLAGS=$(shell echo ${FLAGS} | awk 'BEGIN {FS="\n"; RS="";OFS="\n";} END { split($$0, N, ","); print substr(N[1], index(N[1], "=")+1) }'))
	$(eval LDFLAGS=$(shell echo ${FLAGS} | awk 'BEGIN {FS="\n"; RS="";OFS="\n";} END { split($$0, N, ","); print substr(N[2], index(N[2], "=")+1) }'))
	@set -e; echo $(CXXFLAGS);
	@set -e; echo $(LDFLAGS);
	@set -e; echo "";
	$(CXX) ${CXXFLAGS} -DH_LIBWEBPG -shared -o "${LIBDIR}/${DISTDIR}/lib${PROJECT}${SOEXT}" webpg.cc ${LDFLAGS}

clean:
	@set -e; echo "cleaning build directory...";
	@set -e; rm -vrf $(BINDIR);
	@set -e; echo "done.";
