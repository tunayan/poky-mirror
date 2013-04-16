DESCRIPTION = "Systemd a init replacement"
HOMEPAGE = "http://www.freedesktop.org/wiki/Software/systemd"

LICENSE = "GPLv2 & LGPLv2.1 & MIT"
LIC_FILES_CHKSUM = "file://LICENSE.GPL2;md5=751419260aa954499f7abaabaa882bbe \
                    file://LICENSE.LGPL2.1;md5=4fbd65380cdd255951079008b364516c \
                    file://LICENSE.MIT;md5=544799d0b492f119fa04641d1b8868ed"

PROVIDES = "udev"

PE = "1"
PR = "r3"

DEPENDS = "kmod docbook-sgml-dtd-4.1-native intltool-native gperf-native acl readline dbus libcap libcgroup tcp-wrappers glib-2.0"
DEPENDS += "${@base_contains('DISTRO_FEATURES', 'pam', 'libpam', '', d)}"

SECTION = "base/shell"

inherit gtk-doc useradd pkgconfig autotools perlnative update-rc.d update-alternatives

SRC_URI = "http://www.freedesktop.org/software/systemd/systemd-${PV}.tar.xz \
           file://touchscreen.rules \
           file://modprobe.rules \
           file://var-run.conf \
           ${UCLIBCPATCHES} \
           file://00-create-volatile.conf \
           file://0002-readahead-chunk-on-spinning-media.patch \
           file://0003-readahead-cleanups.patch \
           file://0013-systemd-sysctl-Handle-missing-etc-sysctl.conf-proper.patch \
           file://0001-configure-use-AC_CHECK_TOOL-for-objcopy-strings-and-.patch \
           file://199-firmware.patch \
           file://init \
          "
SRC_URI[md5sum] = "4bb13f84ce211e93f0141774a90a2322"
SRC_URI[sha256sum] = "8c4462a04f3ecf7f083782e5e0687913b1d33c6444bf20fa2f31df9222965fed"

UCLIBCPATCHES = ""
UCLIBCPATCHES_libc-uclibc = "file://systemd-pam-configure-check-uclibc.patch \
                             file://systemd-pam-fix-execvpe.patch \
                             file://systemd-pam-fix-fallocate.patch \
                             file://systemd-pam-fix-getty-unit.patch \
                             file://systemd-pam-fix-mkostemp.patch \
                             file://systemd-pam-fix-msformat.patch \
                             file://optional_secure_getenv.patch \
                            "
LDFLAGS_libc-uclibc_append = " -lrt"

GTKDOC_DOCDIR = "${S}/docs/"

PACKAGECONFIG ??= "xz"
# Sign the journal for anti-tampering
PACKAGECONFIG[gcrypt] = "--enable-gcrypt,--disable-gcrypt,libgcrypt"
# Compress the journal
PACKAGECONFIG[xz] = "--enable-xz,--disable-xz,xz"

CACHED_CONFIGUREVARS = "ac_cv_path_KILL=${base_bindir}/kill"

# The gtk+ tools should get built as a separate recipe e.g. systemd-tools
EXTRA_OECONF = " --with-rootprefix=${base_prefix} \
                 --with-rootlibdir=${base_libdir} \
                 ${@base_contains('DISTRO_FEATURES', 'pam', '--enable-pam', '--disable-pam', d)} \
                 --enable-xz \
                 --disable-manpages \
                 --disable-coredump \
                 --disable-introspection \
                 --disable-tcpwrap \
                 --enable-split-usr \
                 --disable-microhttpd \
                 --without-python \
                 --with-sysvrcnd-path=${sysconfdir} \
                 --with-firmware-path=/lib/firmware \
                 ac_cv_path_KILL=${base_bindir}/kill \
               "
# uclibc does not have NSS
EXTRA_OECONF_append_libc-uclibc = " --disable-myhostname "

# There's no docbook-xsl-native, so for the xsltproc check to false
do_configure_prepend() {
	export CPP="${HOST_PREFIX}cpp ${TOOLCHAIN_OPTIONS} ${HOST_CC_ARCH}"

	export STRINGS="${HOST_PREFIX}strings"
	export GPERF="${HOST_PREFIX}gperf"

	sed -i -e 's:=/root:=${ROOT_HOME}:g' units/*.service*
}

EXTRA_OEMAKE = "rootlibexecdir=${base_sbindir}/systemd \
                udevlibexecdir=${base_sbindir}/udev"

do_install() {
	autotools_do_install
	install -d ${D}/${base_sbindir}
	# provided by a seperate recipe
	rm ${D}${systemd_unitdir}/system/serial-getty* -f

	# provide support for initramfs
	ln -s ${base_sbindir}/systemd/systemd ${D}/init
	ln -s ${base_sbindir}/systemd/systemd-udevd ${D}/${base_sbindir}/udev/udevd

	# create dir for journal
	install -d ${D}${localstatedir}/log/journal

	# create machine-id
	# 20:12 < mezcalero> koen: you have three options: a) run systemd-machine-id-setup at install time, b) have / read-only and an empty file there (for stateless) and c) boot with / writable
	touch ${D}${sysconfdir}/machine-id

	install -m 0644 ${WORKDIR}/*.rules ${D}${sysconfdir}/udev/rules.d/

	install -m 0644 ${WORKDIR}/var-run.conf ${D}${sysconfdir}/tmpfiles.d/

	install -m 0644 ${WORKDIR}/00-create-volatile.conf ${D}${sysconfdir}/tmpfiles.d/

	if ${@base_contains('DISTRO_FEATURES','sysvinit','true','false',d)}; then
		install -d ${D}${sysconfdir}/init.d
		install -m 0755 ${WORKDIR}/init ${D}${sysconfdir}/init.d/systemd-udevd
		sed -i s%@UDEVD@%${base_sbindir}/systemd/systemd-udevd% ${D}${sysconfdir}/init.d/systemd-udevd
	fi
}

python populate_packages_prepend (){
    systemdlibdir = d.getVar("base_libdir", True)
    do_split_packages(d, systemdlibdir, '^lib(.*)\.so\.*', 'lib%s', 'Systemd %s library', extra_depends='', allow_links=True)
}
PACKAGES_DYNAMIC += "^lib(udev|gudev|systemd).*"

PACKAGES =+ "${PN}-gui ${PN}-vconsole-setup ${PN}-initramfs ${PN}-analyze ${PN}-kernel-install"

USERADD_PACKAGES = "${PN}"
GROUPADD_PARAM_${PN} = "-r lock; -r systemd-journal"

FILES_${PN}-analyze = "${bindir}/systemd-analyze"

FILES_${PN}-initramfs = "/init"
RDEPENDS_${PN}-initramfs = "${PN}"

FILES_${PN}-gui = "${bindir}/systemadm"

FILES_${PN}-vconsole-setup = "${systemd_unitdir}/systemd-vconsole-setup \
                              ${systemd_unitdir}/system/systemd-vconsole-setup.service \
                              ${systemd_unitdir}/system/sysinit.target.wants/systemd-vconsole-setup.service"

FILES_${PN}-kernel-install = "${bindir}/kernel-install \
                              ${sysconfdir}/kernel/ \
                              ${exec_prefix}/lib/kernel \
                             "
RRECOMMENDS_${PN}-vconsole-setup = "kbd kbd-consolefonts"

CONFFILES_${PN} = "${sysconfdir}/systemd/journald.conf \
                ${sysconfdir}/systemd/logind.conf \
                ${sysconfdir}/systemd/system.conf \
                ${sysconfdir}/systemd/user.conf"

FILES_${PN} = " ${base_bindir}/* \
                ${base_sbindir}/systemd \
                ${base_sbindir}/systemd/system-generators \
                ${base_sbindir}/udev \
                ${datadir}/bash-completion \
                ${datadir}/dbus-1/services \
                ${datadir}/dbus-1/system-services \
                ${datadir}/polkit-1 \
                ${datadir}/${BPN} \
                ${sysconfdir}/bash_completion.d/ \
                ${sysconfdir}/binfmt.d/ \
                ${sysconfdir}/dbus-1/ \
                ${sysconfdir}/machine-id \
                ${sysconfdir}/modules-load.d/ \
                ${sysconfdir}/sysctl.d/ \
                ${sysconfdir}/systemd/ \
                ${sysconfdir}/tmpfiles.d/ \
                ${sysconfdir}/xdg/ \
                ${sysconfdir}/init.d/README \
                ${systemd_unitdir}/* \
                ${systemd_unitdir}/system/* \
                /lib/udev/rules.d/99-systemd.rules \
                ${base_libdir}/security/*.so \
                ${libdir}/libnss_myhostname.so.2 \
                /cgroup \
                ${bindir}/systemd* \
                ${bindir}/localectl \
                ${bindir}/hostnamectl \
                ${bindir}/timedatectl \
                ${bindir}/bootctl \
                ${bindir}/kernel-install \
                ${exec_prefix}/lib/tmpfiles.d/*.conf \
                ${exec_prefix}/lib/systemd \
                ${exec_prefix}/lib/binfmt.d \
                ${exec_prefix}/lib/modules-load.d \
                ${exec_prefix}/lib/sysctl.d \
                ${localstatedir} \
                /lib/udev/rules.d/70-uaccess.rules \
                /lib/udev/rules.d/71-seat.rules \
                /lib/udev/rules.d/73-seat-late.rules \
                /lib/udev/rules.d/99-systemd.rules \
               "

FILES_${PN}-dbg += "${systemd_unitdir}/.debug ${systemd_unitdir}/*/.debug ${base_libdir}/security/.debug/ ${base_sbindir}/systemd/.debug ${base_sbindir}/systemd/system-generators/.debug ${base_sbindir}/udev/.debug"
FILES_${PN}-dev += "${base_libdir}/security/*.la ${datadir}/dbus-1/interfaces/ ${sysconfdir}/rpm/macros.systemd"

RDEPENDS_${PN} += "dbus util-linux-mount"

RRECOMMENDS_${PN} += "systemd-serialgetty systemd-compat-units \
                      util-linux-agetty \
                      util-linux-fsck e2fsprogs-e2fsck \
                      kernel-module-autofs4 kernel-module-unix kernel-module-ipv6 \
"

PACKAGES =+ "udev-dbg udev-hwdb udev udev-consolekit udev-utils"

FILES_udev-dbg += "${base_sbindir}/udev/.debug"

RDEPENDS_udev += "udev-utils"
RPROVIDES_udev = "hotplug"
RRECOMMENDS_udev += "udev-extraconf udev-hwdb"

FILES_udev += "${base_sbindir}/udevd \
               ${base_sbindir}/systemd/systemd-udevd \
               ${base_sbindir}/udev \
               ${sysconfdir}/udev \
               ${sysconfdir}/init.d/systemd-udevd \
               ${systemd_unitdir}/system/*udev* \
               ${systemd_unitdir}/system/*.wants/*udev* \
              "

FILES_udev-consolekit += "/lib/ConsoleKit"
RDEPENDS_udev-consolekit += "${@base_contains('DISTRO_FEATURES', 'x11', 'consolekit', '', d)}"

FILES_udev-utils = "${base_bindir}/udevadm ${datadir}/bash-completion/completions/udevadm"

FILES_udev-hwdb = "${base_sbindir}/udev/hwdb.d"

INITSCRIPT_PACKAGES = "udev"
INITSCRIPT_NAME_udev = "systemd-udevd"
INITSCRIPT_PARAMS_udev = "start 03 S ."

python __anonymous() {
    features = d.getVar("DISTRO_FEATURES", True).split()
    if "sysvinit" not in features:
        d.setVar("INHIBIT_UPDATERCD_BBCLASS", "1")
}

# TODO:
# u-a for runlevel and telinit

ALTERNATIVE_${PN} = "init halt reboot shutdown poweroff"

ALTERNATIVE_TARGET[init] = "${base_sbindir}/systemd/systemd"
ALTERNATIVE_LINK_NAME[init] = "${base_sbindir}/init"
ALTERNATIVE_PRIORITY[init] ?= "300"

ALTERNATIVE_TARGET[halt] = "${base_bindir}/systemctl"
ALTERNATIVE_LINK_NAME[halt] = "${base_sbindir}/halt"
ALTERNATIVE_PRIORITY[halt] ?= "300"

ALTERNATIVE_TARGET[reboot] = "${base_bindir}/systemctl"
ALTERNATIVE_LINK_NAME[reboot] = "${base_sbindir}/reboot"
ALTERNATIVE_PRIORITY[reboot] ?= "300"

ALTERNATIVE_TARGET[shutdown] = "${base_bindir}/systemctl"
ALTERNATIVE_LINK_NAME[shutdown] = "${base_sbindir}/shutdown"
ALTERNATIVE_PRIORITY[shutdown] ?= "300"

ALTERNATIVE_TARGET[poweroff] = "${base_bindir}/systemctl"
ALTERNATIVE_LINK_NAME[poweroff] = "${base_sbindir}/poweroff"
ALTERNATIVE_PRIORITY[poweroff] ?= "300"

pkg_postinst_udev-hwdb () {
	if test -n "$D"; then
		exit 1
	fi

	udevadm hwdb --update
}

pkg_prerm_udev-hwdb () {
	if test -n "$D"; then
		exit 1
	fi

	rm -f ${sysconfdir}/udev/hwdb.bin
}

# As this recipe builds udev, respect the systemd DISTRO_FEATURE so we don't try
# building udev and systemd in world builds.
python () {
    if not oe.utils.contains ('DISTRO_FEATURES', 'systemd', True, False, d):
        raise bb.parse.SkipPackage("'systemd' not in DISTRO_FEATURES")
}
