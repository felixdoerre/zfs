AC_DEFUN([ZFS_AC_CONFIG_ALWAYS_PAM], [
	AC_ARG_ENABLE([pam],
		AS_HELP_STRING([--enable-pam],
		[install pam_zfs_key module [[default: check]]]),
		[enable_pam=$enableval],
		[enable_pam=check])

	AC_ARG_WITH(pammoduledir,
		AS_HELP_STRING([--with-pammoduledir=DIR],
		[install pam module in dir [[/lib/security]]]),
		[pammoduledir="$withval"],[pammoduledir=/lib/security])

	AC_ARG_WITH(pamconfigsdir,
		AS_HELP_STRING([--with-pamconfigsdir=DIR],
		[install pam-config files in dir [[/usr/share/pamconfigs]]]),
		[pamconfigsdir="$withval"],[pamconfigsdir=/usr/share/pam-configs])

	AS_IF([test "x$enable_pam" != "xno"], [
		AC_CHECK_HEADERS([security/pam_modules.h security/pam_ext.h], [
			enable_pam=yes
		], [
			AS_IF([test "x$enable_pam" == "xyes"], [
				AC_MSG_FAILURE([
	*** security/pam_modules.h missing, libpam0g-dev package required
				])
			])
		])
	])
	AS_IF([test "x$enable_pam" == "xyes"], [
		DEFINE_PAM='--define "_pam 1" --define "_pammoduledir $(pammoduledir)" --define "_pamconfigsdir $(pamconfigsdir)"'
	])
	AC_SUBST(DEFINE_PAM)
	AM_CONDITIONAL([PAM_ZFS_ENABLED], [test "x$enable_pam" = xyes])
	AC_SUBST(pammoduledir)
	AC_SUBST(pamconfigsdir)
])
