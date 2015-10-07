AC_INIT([cheetah AES],[1.0])
# Safety check that this configure is in the right position
AC_CONFIG_SRCDIR([src/cheetah.c])
AM_INIT_AUTOMAKE(subdir-objects)
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

AC_CHECK_LIB([osal],[l2b],,[AC_MSG_ERROR([Could not find OSal])],-lpthread  )

AC_CHECK_LIB([osalposix],[OperatingEnvironment_New],,[AC_MSG_ERROR([Could not find OSalPosix])],-lpthread  )

AC_CHECK_LIB([encoding], [i2b],,[AC_MSG_ERROR([Could not find encoding])], -losalposix -losal -lpthread )

AC_CHECK_LIB([datetime], [DateTime_New],,[AC_MSG_ERROR([Could not find datetime])], -losalposix -losal -lpthread)

AC_CHECK_LIB([ds],[HashMap_new],,[AC_MSG_ERROR([Could not find ds]), -losalposix -losal   -lpthread])

AC_CHECK_LIB([utils],[Options_New],,[AC_MSG_ERROR([Could not find utils])],-losal -losalposix -lpthread  )

AC_CHECK_LIB([math],[new_matrix],,[AC_MSG_ERROR([Could not find math])],)

AC_CHECK_LIB([cminimacs],[GenericMulParMiniMacs_DefaultLoadNew],,[AC_MSG_ERROR([Could not find MiniMac])], -lcarena -lds -lencoding -lmath -losalposix -losal)

AC_CHECK_LIB([carena],[CArena_new],,[AC_MSG_ERROR([Could not find CArena])], -lds -lencoding -lmath -losalposix -losal)


AC_CONFIG_FILES([Makefile 
          include/Makefile
          src/Makefile
   	      test/Makefile
          ])
# List the makefiles that configure should care about creating (in cooperation with automake)
AC_OUTPUT



