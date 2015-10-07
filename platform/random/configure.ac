define([svnversion], esyscmd([sh -c "svnversion|tr -d '\n'"]))dnl
define([buildtime], esyscmd([sh -c "date +\"build:%Y-%m-%d %H:%M:%S\"|tr -d '\n'"]))dnl
AC_DEFINE(SVN_REVISION, "svnversion", [SVN Revision])
AC_DEFINE(BUILD_TIME,"buildtime",[Build Time])dnl
AC_DEFINE(CODENAME, "Random", [CODE Name])
AC_INIT([random],[1.0])
AC_CONFIG_SRCDIR([src/random.c])
AM_INIT_AUTOMAKE
AC_PREREQ(2.12)
AM_CONFIG_HEADER(config.h:config.in)
AC_PROG_CC
AC_PROG_RANLIB
AM_CONDITIONAL(OSX,test x`uname` = "xDarwin")
if test x`uname ` = "xDarwin";
then
AC_DEFINE([MAC_OS_X],[1],[Assuming we are building on MAC OSX])
else
AC_CHECK_LIB([rt],[clock_gettime],,[AC_MSG_ERROR([Could not find pthread])],)
fi
AC_CHECK_LIB([pthread],[pthread_create],,[AC_MSG_ERROR([Could not find pthread])],)
AC_CHECK_LIB([osal],[l2b],,[AC_MSG_ERROR([Could not find OSal])],-lpthread)
AC_CHECK_LIB([osalposix],[OperatingEnvironment_New],,[AC_MSG_ERROR([Could not find OSalPosix])],-lpthread)

# List the makefiles that configure should care about creating (in cooperation with automake)
AC_OUTPUT([Makefile 
          include/Makefile
          src/Makefile
	  test/Makefile
          ])


