#!/bin/bash
CXX=$1
BUILDTYPE=$2
PROJECT=webpg
PROJECT_ROOT=$(pwd)
BINDIR=$PROJECT_ROOT/build/bin
LIBDIR=$PROJECT_ROOT/build/lib
BINEXT=
SOEXT=.so
OUTPUTNAME=config_test_$(date +%s)

if [ "$(type getconf 2>&1 | awk -v pat="not found" 'BEGIN {FS="\n"; RS="";OFS="\n";} $0 ~ pat { print "NOT_FOUND" };')" == "NOT_FOUND" ]
then
  LBITS=$(file /bin/cp | awk -v pat="32" 'BEGIN {FS="\n"; RS="";OFS="\n";} $0 ~ pat { print pat };')
else
  LBITS=$(getconf LONG_BIT)
fi

if [ "$(uname | awk -v pat="MINGW" 'BEGIN {FS="\n"; RS="";OFS="\n";} $0 ~ pat { print pat };')" == "MINGW" ]
then
  UNAME=$(uname -o)
else
  UNAME=$(uname)
fi

QUOTE=""

case "$UNAME" in
  "Darwin" )
    PLATFORM='macosx'
    DISTDIR='Darwin_x86_64-gcc'
    SOEXT='.dylib'
    CXXFLAGS='-arch i386 -arch x86_64 -DFB_MACOSX '
    PLDFLAGS="${PROJECT_ROOT}/libs/libcurl/${DISTDIR}/libcyassl.a \
	      ${PROJECT_ROOT}/libs/libcurl/${DISTDIR}/libz.a"
    ;;
  "FreeBSD" )
    PLATFORM='bsd'
    if [ $LBITS -eq 64 ]
    then
      DISTDIR='BSD_x86_64-gcc'
    else
      DISTDIR='BSD_x86-gcc'
    fi
    ;;
  "NetBSD" )
    PLATFORM=bsd
    if [ $LBITS -eq 64 ]
    then
      DISTDIR='BSD_x86_64-gcc'
    else
      DISTDIR='BSD_x86-gcc'
    fi
    ;;
  "OpenBSD" )
    PLATFORM=bsd
    if [ $LBITS -eq 64 ]
    then
      DISTDIR='BSD_x86_64-gcc'
    else
      DISTDIR='BSD_x86-gcc'
    fi
    ;;
  "DragonFly" )
    PLATFORM=bsd
    if [ $LBITS -eq 64 ]
    then
      DISTDIR=BSD_x86_64-gcc
    else
      DISTDIR=BSD_x86-gcc
    fi
    ;;
  "Msys" )
    QUOTE="'"
    PLATFORM='mingw'
    BINEXT='.exe'
    SOEXT='.dll'
    CXXFLAGS+=' -DHAVE_W32_SYSTEM'
    PLDFLAGS+='-lwsock32 -lgdi32 -lws2_32'
    if [ "$TARGET_CPU" == "x86_64" ]
    then
      DISTDIR='WINNT_x86_64-msvc'
    else
      DISTDIR='WINNT_x86-msvc'
    fi
    ;;
  "Cygwin" )
    QUOTE="'"
    PLATFORM='cygwin'
    BINEXT='.exe'
    SOEXT='.dll'
    CXXFLAGS+=' -DHAVE_W32_SYSTEM'
    if [ "$TARGET_CPU" == "x86_64" ]
    then
      DISTDIR='WINNT_x86_64-msvc'
    else
      DISTDIR='WINNT_x86-msvc'
    fi
    ;;
  "Linux" )
    PLATFORM='linux'
    PLDFLAGS="-lrt"
    if [ $LBITS -eq 64 ]
    then
      DISTDIR=Linux_x86_64-gcc
    else
      DISTDIR=Linux_x86-gcc
    fi
    if [ "$(uname -m | grep -oP 'armv[\d][\w]' | grep -oP 'arm')" == "arm" ]
    then
      DISTDIR="Linux_armv$(uname -m | grep -oP 'armv[\d][\w]' | grep -oP '[\d]')-gcc"
    fi
    ;;
  * )
    PLATFORM=unix
    if [ $LBITS -eq 64 ]
    then
      DISTDIR='Linux_x86_64-gcc'
    else
      DISTDIR='Linux_x86-gcc'
    fi
    if [ $(uname -m | grep -oP 'armv[\d][\w]' | grep -oP 'arm') == "arm" ]
    then
      DISTDIR="Linux_armv$(uname -m | grep -oP 'armv[\d][\w]' | grep -oP '[\d]')-gcc"
      PLDFLAGS+='-lm'
    fi
    ;;
esac

$({ $CXX &>/dev/null; })
if [ $? -eq 127 ]
then
  exit $?
fi

>&2 echo "Generating test for ${CXX}"
if [ -z "${CXX##clang}" ]
then
  >&2 echo "Added flags clang"
  STATIC_GCC="-lm -lstdc++"
elif [ -z "${CXX##clang*}" ]
then
  >&2 echo "Added flags clang++"
  STATIC_GCC="-static-libgcc"
else
  >&2 echo "Added flags ${CXX}"
  CXXFLAGS+=" -Wno-unused-local-typedefs"
fi

LDFLAGS="$QUOTE$PROJECT_ROOT/libs/libgpgme/$DISTDIR/libgpgme.a$QUOTE
  $QUOTE$PROJECT_ROOT/libs/libgpg-error/$DISTDIR/libgpg-error.a$QUOTE
  $QUOTE$PROJECT_ROOT/libs/libassuan/$DISTDIR/libassuan.a$QUOTE
  $QUOTE$PROJECT_ROOT/libs/jsoncpp/$DISTDIR/libjsoncpp.a$QUOTE
  $QUOTE$PROJECT_ROOT/libs/libmimetic/$DISTDIR/libmimetic.a$QUOTE
  $QUOTE$PROJECT_ROOT/libs/libcurl/$DISTDIR/libcurl.a$QUOTE
  $PLDFLAGS"

CXXFLAGS+=" -I $QUOTE$PROJECT_ROOT/libs/boost/include$QUOTE
  -I $QUOTE$PROJECT_ROOT/libs/libgpgme/$DISTDIR/include$QUOTE
  -I $QUOTE$PROJECT_ROOT/libs/libgpg-error/$DISTDIR/include$QUOTE
  -I $QUOTE$PROJECT_ROOT/libs/libmimetic/$DISTDIR/include$QUOTE
  -I $QUOTE$PROJECT_ROOT/libs/libcurl/$DISTDIR/include$QUOTE
  -D _FILE_OFFSET_BITS=64 -DDEBUG -DCURL_STATICLIB
  -g -Wall -O2 -fPIC $STATIC_GCC"

if [ $BUILDTYPE == "STATIC" ]
then
  OPT="-static"
else
  OPT="-shared"
fi

# Test which is needed to statically include libstdc++
>&2 echo "${CXX} ${OPT} ${CXXFLAGS} -static-libstdc++ tests/list.c ${LDFLAGS}"
TESTFLAGS=' '$({ ${CXX} ${OPT} ${CXXFLAGS} -static-libstdc++ tests/list.c -o /tmp/$OUTPUTNAME ${LDFLAGS} 2>&1 | \
  awk -v pat="$CXX" -v ret="" 'BEGIN {FS="\n"; RS="";OFS="\n";} $0 ~ pat { \
   if ($0 ~ "option" || $0 ~ "argument") {\
     pat " -print-file-name=libstdc++.a"|getline ret; \
     if (ret != "libstdc++.a") \
      print ret; \
   } else {\
     print "-static-libstdc++"; \
   }\
  }';
})

>&2 echo "    checking ${OPT} build"
>&2 echo "    GCC LINK: $STATIC_GCC"
>&2 echo "    TESTFLAGS: $TESTFLAGS"

if [[ $TESTFLAGS =~ static-libstdc ]]
then
    TESTCOMPILE="${CXX} ${TESTFLAGS} ${CXXFLAGS} -DH_LIBWEBPG ${OPT} -o /tmp/$OUTPUTNAME webpg.cc ${LDFLAGS}"
else
    TESTCOMPILE="${CXX} ${CXXFLAGS} -DH_LIBWEBPG ${OPT} -o /tmp/$OUTPUTNAME webpg.cc ${TESTFLAGS} ${LDFLAGS}"
fi

# Test if the static libstdc++ file was compilied with fPIC
TESTRES=$({ ${TESTCOMPILE} 2>&1 | \
    awk -v ret="$TESTFLAGS" 'BEGIN {FS="\n"; RS="";OFS="\n";} { if ($0 ~ /libstdc\+\+\.a.*?relocation/) { \
      ret="-lstdc++"; \
      print "    TESTCOMPILE Result: " $0 > "/dev/stderr"; \
    }
  } END { \
    print ret; \
  }';
})

>&2 echo "    TESTFLAGS: $TESTFLAGS"
>&2 echo "    TESTRES: $TESTRES"

if [ -f /tmp/$OUTPUTNAME ]
then
  rm /tmp/$OUTPUTNAME
fi

if [[ $TESTFLAGS =~ static-libstdc ]]
then
  CXXFLAGS=$TESTRES' '$CXXFLAGS
else
  LDFLAGS=$TESTRES' '$LDFLAGS
fi

echo -e "CXXFLAGS=${CXXFLAGS},LDFLAGS=${LDFLAGS}"
