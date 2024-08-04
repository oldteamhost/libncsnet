AC_PREREQ([2.69])
AC_INIT([libncsnet], [20240530])
AC_CONFIG_HEADERS([config.h:config.h.in])

dnl check compiler
AC_PROG_CC

dnl flags
CFLAGS="-Wall -fPIC -DHAVE_CONFIG_H -march=native -mtune=native -g -flto"
OCFLAGS="-O3 -fforce-addr"
AC_SUBST(CFLAGS)
AC_SUBST(OCFLAGS)

dnl other
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

dnl check OS
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

dnl check make util
MAKE_P="make"
AC_MSG_CHECKING([for make util])
if test "$OS_TYPE" = "bsd"; then
  MAKE_P="gmake"
fi
AC_MSG_RESULT([$MAKE_P])
AC_SUBST(MAKE_P)

dnl check devide op
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

dnl check wordsize
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

dnl check netdb funcs
AC_CHECK_FUNCS([htons])
if test "x$ac_cv_func_htons" = "xno"; then
  AC_DEFINE([HAVE_NETDB_HOST], [1], [Define to 1 if you have no htons function.])
fi

dnl linux read
AC_ARG_ENABLE([linuxread],
    AS_HELP_STRING([--disable-linuxread],
                   [Disable linuxread support (default is enabled)]),
    [linuxread_disable=yes],
    [linuxread_disable=no])

AC_DEFINE([HAVE_LINUX_READ], [1], [Enable linuxread support by default])
AC_MSG_NOTICE([linuxread support is enabled by default])
if test "x$linuxread_disable" = "xyes"; then
    AC_DEFINE_UNQUOTED([HAVE_LINUX_READ], [0], [linuxread support disabled])
    AC_MSG_NOTICE([linuxread support is disabled])
else
    AC_MSG_NOTICE([linuxread support is enabled])
fi

UTILS_PATH="utils/Makefile"
AC_CHECK_FILE([$UTILS_PATH], [UTILS_FOUND=yes], [UTILS_FOUND=no])
if test "$UTILS_FOUND" = "no"; then
    echo "utils (Makefile) not found, configuring utils"
    echo ""
    echo "RUNNING CONFIGURE UTILS/"
    echo ""
    (cd utils;./configure;cd ..)
else
    echo "utils (Makefile) found, no need to configure"
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
