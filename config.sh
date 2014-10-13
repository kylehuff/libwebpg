#!/bin/bash
CXX=$1
FLAGTYPE=$2
PROJECT=webpg
PROJECT_ROOT=$(pwd)
BINDIR=$PROJECT_ROOT/build/bin
LIBDIR=$PROJECT_ROOT/build/lib
BINEXT=
SOEXT=.so
OUTPUTNAME=config_test_$(date +%s)

LBITS=$(getconf LONG_BIT)
UNAME=$(uname)

get_platform() {
    local x = 1;
}

case "$UNAME" in
  "Darwin" )
    PLATFORM='macosx'
    DISTDIR='Darwin_x86_64-gcc'
    SOEXT='.dylib'
    CXXFLAGS='-arch i386 -arch x86_64 -DFB_MACOSX'
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
    PLATFORM='mingw'
    BINEXT='.exe'
    SOEXT='.dll'
    CXXFLAGS+=' -DHAVE_W32_SYSTEM'
    LDFLAGS+='-lwsock32 -lgdi32 -lws2_32'
    if [ "$TARGET_CPU" == "x86_64" ]
    then
      DISTDIR='WINNT_x86_64-msvc'
    else
      DISTDIR='WINNT_x86-msvc'
    fi
    ;;
  "Cygwin" )
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
    PLDFLAGS='-ldl -lrt -lm'
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

LDFLAGS="$PROJECT_ROOT/libs/libgpgme/$DISTDIR/libgpgme.a
  $PROJECT_ROOT/libs/libgpg-error/$DISTDIR/libgpg-error.a
  $PROJECT_ROOT/libs/libassuan/$DISTDIR/libassuan.a
  $PROJECT_ROOT/libs/jsoncpp/$DISTDIR/libjsoncpp.a
  $PROJECT_ROOT/libs/libmimetic/$DISTDIR/libmimetic.a
  $PROJECT_ROOT/libs/libcurl/$DISTDIR/libcurl.a
  $PLDFLAGS"

CXXFLAGS+="-I $PROJECT_ROOT/libs/boost/include
  -I $PROJECT_ROOT/libs/libgpgme/$DISTDIR/include
  -I $PROJECT_ROOT/libs/libgpg-error/$DISTDIR/include
  -I $PROJECT_ROOT/libs/libmimetic/$DISTDIR/include
  -I $PROJECT_ROOT/libs/libcurl/$DISTDIR/include
  -D _FILE_OFFSET_BITS=64 -DDEBUG -DCURL_STATICLIB
  -g -Wall -O2 -fPIC -static-libgcc"

# Test which is needed to statically include libstdc++
TESTFLAGS=' '$({ ${CXX} -static-libstdc++ tests/list.c 2>&1 | \
  awk -v pat="$CXX" '$0 ~ pat { \
   if ($3 == "option" || $3 == "argument") \
     system(pat " -print-file-name=libstdc++.a"); \
   else \
     print "-static-libstdc++"; \
     exit; \
  }';
})

>&2 echo $TESTFLAGS

# Test if the static libstdc++ file was compilied with fPIC
TESTRES=$({ ${CXX} ${TESTFLAGS} ${CXXFLAGS} tests/config.cpp -o /tmp/$OUTPUTNAME ${LDFLAGS} 2>&1 | \
  awk -v ret="$TESTFLAGS" '/libstdc\+\+\.a.*?relocation/ { \
    ret="-lstdc++"; \
  } END { \
    print ret; \
  }';
})

>&2 echo $TESTRES

if [ -f /tmp/$OUTPUTNAME ]
then
  rm /tmp/$OUTPUTNAME
fi

if [[ $TESTFLAGS =~ static-libstdc ]]
then
  CXXFLAGS=$TESTRES' '$CXXFLAGS
else
  LDFLAGS=$LDFLAGS' '$TESTFLAGS
fi

if [ $FLAGTYPE == "CXXFLAGS" ]
then
  echo ${CXXFLAGS}
elif [ $FLAGTYPE == "LDFLAGS" ]
then
  echo  ${LDFLAGS}
fi
