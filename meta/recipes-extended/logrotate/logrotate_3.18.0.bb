SUMMARY = "Rotates, compresses, removes and mails system log files"
SECTION = "console/utils"
HOMEPAGE = "https://github.com/logrotate/logrotate/"
DESCRIPTION = "The logrotate utility is designed to simplify the administration of log files on a system which generates a lot of log files."
LICENSE = "GPLv2"

# TODO: Document coreutils dependency. Why not RDEPENDS? Why not busybox?

DEPENDS="coreutils popt"

LIC_FILES_CHKSUM = "file://COPYING;md5=b234ee4d69f5fce4486a80fdaf4a4263"

UPSTREAM_CHECK_URI = "https://github.com/${BPN}/${BPN}/releases"
UPSTREAM_CHECK_REGEX = "logrotate-(?P<pver>\d+(\.\d+)+).tar"

SRC_URI = "https://github.com/${BPN}/${BPN}/releases/download/${PV}/${BP}.tar.xz \
            file://act-as-mv-when-rotate.patch \
            file://0001-Update-the-manual.patch \
            file://disable-check-different-filesystems.patch \
            "

SRC_URI[sha256sum] = "841f81bf09d0014e4a2e11af166bb33fcd8429cc0c2d4a7d3d9ceb3858cfccc5"

# These CVEs are debian, gentoo or SUSE specific on the way logrotate was installed/used
CVE_CHECK_WHITELIST += "CVE-2011-1548 CVE-2011-1549 CVE-2011-1550"

PACKAGECONFIG ?= "${@bb.utils.filter('DISTRO_FEATURES', 'acl selinux', d)}"

PACKAGECONFIG[acl] = ",,acl"
PACKAGECONFIG[selinux] = ",,libselinux"

CONFFILES_${PN} += "${localstatedir}/lib/logrotate.status \
                    ${sysconfdir}/logrotate.conf \
                    ${sysconfdir}/logrotate.d/btmp \
                    ${sysconfdir}/logrotate.d/wtmp"

# If RPM_OPT_FLAGS is unset, it adds -g itself rather than obeying our
# optimization variables, so use it rather than EXTRA_CFLAGS.
EXTRA_OEMAKE = "\
    LFS= \
    OS_NAME='${OS_NAME}' \
    'CC=${CC}' \
    'RPM_OPT_FLAGS=${CFLAGS}' \
    'EXTRA_LDFLAGS=${LDFLAGS}' \
    ${@bb.utils.contains('PACKAGECONFIG', 'acl', 'WITH_ACL=yes', '', d)} \
    ${@bb.utils.contains('PACKAGECONFIG', 'selinux', 'WITH_SELINUX=yes', '', d)} \
"

# OS_NAME in the makefile defaults to `uname -s`. The behavior for
# freebsd/netbsd is questionable, so leave it as Linux, which only sets
# INSTALL=install and BASEDIR=/usr.
OS_NAME = "Linux"

inherit autotools systemd

SYSTEMD_SERVICE_${PN} = "\
    ${BPN}.service \
    ${BPN}.timer \
"

LOGROTATE_OPTIONS ?= ""

LOGROTATE_SYSTEMD_TIMER_BASIS ?= "daily"
LOGROTATE_SYSTEMD_TIMER_ACCURACY ?= "12h"
LOGROTATE_SYSTEMD_TIMER_PERSISTENT ?= "true"

do_install(){
    oe_runmake install DESTDIR=${D} PREFIX=${D} MANDIR=${mandir}
    mkdir -p ${D}${sysconfdir}/logrotate.d
    mkdir -p ${D}${localstatedir}/lib
    install -p -m 644 ${S}/examples/logrotate.conf ${D}${sysconfdir}/logrotate.conf
    install -p -m 644 ${S}/examples/btmp ${D}${sysconfdir}/logrotate.d/btmp
    install -p -m 644 ${S}/examples/wtmp ${D}${sysconfdir}/logrotate.d/wtmp
    touch ${D}${localstatedir}/lib/logrotate.status

    if ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'true', 'false', d)}; then
        install -d ${D}${systemd_system_unitdir}
        install -m 0644 ${S}/examples/logrotate.service ${D}${systemd_system_unitdir}/logrotate.service
        install -m 0644 ${S}/examples/logrotate.timer ${D}${systemd_system_unitdir}/logrotate.timer
        [ -z "${LOGROTATE_OPTIONS}" ] ||
            sed -ri \
                -e 's|(ExecStart=.*/logrotate.*)$|\1 ${LOGROTATE_OPTIONS}|g' \
                ${D}${systemd_system_unitdir}/logrotate.service
        sed -ri \
            -e 's|(OnCalendar=).*$|\1${LOGROTATE_SYSTEMD_TIMER_BASIS}|g' \
            -e 's|(AccuracySec=).*$|\1${LOGROTATE_SYSTEMD_TIMER_ACCURACY}|g' \
            -e 's|(Persistent=).*$|\1${LOGROTATE_SYSTEMD_TIMER_PERSISTENT}|g' \
            ${D}${systemd_system_unitdir}/logrotate.timer
    fi

    if ${@bb.utils.contains('DISTRO_FEATURES', 'sysvinit', 'true', 'false', d)}; then
        mkdir -p ${D}${sysconfdir}/cron.daily
        install -p -m 0755 ${S}/examples/logrotate.cron ${D}${sysconfdir}/cron.daily/logrotate
    fi
}
