AC_PREREQ([2.69])
AC_INIT([libncsnet], [20240530])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_PROG_CC
CFLAGS="-Wall -fPIC -DHAVE_CONFIG_H -march=native -mtune=native -g -flto"
OCFLAGS="-O3 -fforce-addr"
AC_SUBST(CFLAGS)
AC_SUBST(OCFLAGS)
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO


dnl
dnl check os
dnl

AC_CANONICAL_HOST
AC_MSG_CHECKING([for operating system])
case "$host_os" in
  *bsd*)
    OS_TYPE=bsd
    AC_DEFINE([IS_BSD], [1], [Define if this is a BSD system])
    AC_MSG_RESULT([$OS_TYPE])
    ;;
  *linux*)
    OS_TYPE=linux
    AC_DEFINE([IS_LINUX], [1], [Define if this is a Linux system])
    AC_MSG_RESULT([$OS_TYPE])
    ;;
  *)
    OS_TYPE=unknown
    ;;
esac


dnl
dnl check make util
dnl

MAKE_P="make"
AC_MSG_CHECKING([for make util])
if test "$OS_TYPE" = "bsd"; then
  MAKE_P="gmake"
fi
AC_MSG_RESULT([$MAKE_P])
AC_SUBST(MAKE_P)


dnl
dnl check devide op
dnl

AC_MSG_CHECKING([whether the processor supports DIVIDE instruction])
AC_COMPILE_IFELSE(
    [AC_LANG_SOURCE([
        int main() {
            int a = 10;
            int b = 2;
            int c;
            asm ("div %1" : "=a" (c) : "r" (b), "a" (a));
            return 0;
        }
    ])],
    [ac_cv_prog_divide_support=yes],
    [ac_cv_prog_divide_support=no]
)
AC_MSG_RESULT([$ac_cv_prog_divide_support])
if test "$ac_cv_prog_divide_support" = yes; then
    AC_DEFINE([HAVE_DIVIDE_SUPPORT], [1], [Define if processor supports DIVIDE instruction])
fi


dnl
dnl check wordsize
dnl

AC_CHECK_SIZEOF([void *], [8])
if test "$ac_cv_sizeof_void_p" = "4"; then
  WORD_SIZE=32
elif test "$ac_cv_sizeof_void_p" = "8"; then
  WORD_SIZE=64
else
  AC_MSG_ERROR([Unsupported word size])
fi
AC_DEFINE_UNQUOTED([WORD_SIZE], [$WORD_SIZE], [Word size in bits])
if test "$ac_cv_c_bigendian" = "yes"; then
  AC_DEFINE([BIG_ENDIAN_SYSTEM], [1], [System is big-endian])
else
  AC_DEFINE([LITTLE_ENDIAN_SYSTEM], [1], [System is little-endian])
fi


dnl
dnl netdb func
dnl

AC_CHECK_FUNCS([htons])
if test "x$ac_cv_func_htons" = "xno"; then
  AC_DEFINE([HAVE_NETDB_HOST], [1], [Define to 1 if you have no htons function.])
fi


dnl
dnl linux read
dnl

AC_ARG_ENABLE([linuxread],
    AS_HELP_STRING([--disable-linuxread],
                   [Disable linuxread support (default is enabled)]),
    [linuxread_disable=yes],
    [linuxread_disable=no])

AC_DEFINE([HAVE_LINUX_READ], [1], [Enable linuxread support by default])
if test "x$linuxread_disable" = "xyes"; then
    AC_DEFINE_UNQUOTED([HAVE_LINUX_READ], [0], [linuxread support disabled])
    AC_MSG_RESULT([checking linuxread support... disabled])
else
    AC_MSG_RESULT([checking linuxread support... enabled])
fi


dnl
dnl MODULES
dnl

BASE_DIRS="src/"

AC_ARG_WITH([base],
    [AS_HELP_STRING([--with-base], [Use specific base module for source files compilation])],
    [BASE_DIRS="src/utils src/hex src/ip4addr src/ip6addr src/mac src/random src/raw src/crypt src/cidr src/url"] BASE_ENABLED=yes)

AC_ARG_WITH([datalink],
    [AS_HELP_STRING([--with-datalink], [Use specific datalink module for source files compilation])],
    [BASE_DIRS="src/utils src/hex src/ip4addr src/ip6addr src/mac src/random src/raw src/crypt src/cidr src/url src/eth src/arp src/route src/intf src/ncsnet src/addr"] DATALINK_ENABLED=yes)

AC_ARG_WITH([network],
    [AS_HELP_STRING([--with-network], [Use specific network module for source files compilation])],
    [BASE_DIRS="src/utils src/hex src/ip4addr src/ip6addr src/mac src/random src/raw src/crypt src/cidr src/url src/eth src/arp src/route src/intf src/ncsnet src/ip src/icmp src/igmp"] NETWORK_ENABLED=yes)

AC_ARG_WITH([transport],
    [AS_HELP_STRING([--with-transport], [Use specific transport module for source files compilation])],
    [BASE_DIRS="src/utils src/hex src/ip4addr src/ip6addr src/mac src/random src/raw src/crypt src/cidr src/url src/eth src/arp src/route src/intf src/ncsnet src/ip src/icmp src/igmp src/tcp src/udp src/sctp src/udplite src/trace"] TRANSPORT_ENABLED=yes)

AC_MSG_RESULT([checking directories for compile... $BASE_DIRS])
SOURCES=$(find $BASE_DIRS -name '*.c' | xargs)
AS_IF([test -z "$SOURCES"], [
    AC_MSG_ERROR([no source files found in the specified directories!])
])
AC_SUBST([SOURCES])


dnl
dnl UTILS
dnl

AS_IF([test -z "$BASE_ENABLED$DATALINK_ENABLED$NETWORK_ENABLED$TRANSPORT_ENABLED"], [
    UTILS_PATH="utils/Makefile"
    AC_CHECK_FILE([$UTILS_PATH], [UTILS_FOUND=yes], [UTILS_FOUND=no])
    if test "$UTILS_FOUND" = "no"; then
        echo "utils (Makefile) not found, configuring utils"
        echo ""
        echo "RUNNING CONFIGURE UTILS/"
        echo ""
        (cd utils; ./configure; cd ..)
    else
        echo "checking utils (Makefile) found, no need to configure"
    fi
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
