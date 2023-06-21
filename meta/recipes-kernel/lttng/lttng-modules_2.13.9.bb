SECTION = "devel"
SUMMARY = "Linux Trace Toolkit KERNEL MODULE"
DESCRIPTION = "The lttng-modules 2.0 package contains the kernel tracer modules"
HOMEPAGE = "https://lttng.org/"
LICENSE = "LGPL-2.1-only & GPL-2.0-only & MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=0464cff101a009c403cd2ed65d01d4c4"

inherit module

include lttng-platforms.inc

SRC_URI = "https://lttng.org/files/${BPN}/${BPN}-${PV}.tar.bz2 \
           file://0009-Rename-genhd-wrapper-to-blkdev.patch \
           file://0001-fix-mm-introduce-vma-vm_flags-wrapper-functions-v6.3.patch \
           file://0002-fix-uuid-Decouple-guid_t-and-uuid_le-types-and-respe.patch \
           file://0003-fix-btrfs-pass-find_free_extent_ctl-to-allocator-tra.patch \
           file://0004-fix-net-add-location-to-trace_consume_skb-v6.3.patch \
file://0001-Fix-syscalls-extractor-kallsyms_lookup_name-no-longe.patch \
file://0002-Add-x86-32-syscall-list-for-kernel-6.0.7.patch \
file://0003-Add-_time32-suffixed-variants-of-syscalls-to-table-s.patch \
file://0004-Support-per-architecture-syscall-in-out-parameter-de.patch \
file://0005-Add-x86-64-syscall-list-for-kernel-6.0.7.patch \
file://0006-Add-arm-64-syscall-list-for-kernel-6.0.7.patch \
file://0007-Add-arm-32-syscall-list-for-kernel-6.0.7.patch \
file://0008-syscall-instrumentation-add-missing-forward-declarat.patch \
file://0009-Add-generated-x86-64-syscall-instrumentation-for-ker.patch \
file://0010-Add-generated-arm-64-syscall-instrumentation-for-ker.patch \
file://0011-Fix-define-old_sigaction-as-compat_old_sigaction-in-.patch \
file://0012-Add-generated-x86-32-syscall-instrumentation-for-ker.patch \
file://0013-Add-generated-arm-32-syscall-instrumentation-for-ker.patch \
file://0014-Fix-add-missing-typedef-and-forward-declarations-for.patch \
file://0015-Fix-system-call-instrumentation-build-failure-on-v3..patch \
file://0016-Fix-Use-ifdef-for-CONFIG_COMPAT_OLD_SIGACTION.patch \
file://0017-Fix-define-old_sigaction-as-compat_old_sigaction-in-.patch \
file://0018-Build-fix-arm64-incomplete-landlock_rule_type-type.patch \
file://0019-Cleanup-unused-Makefile.patch \
file://0020-Split-syscalls-headers-and-tools.patch \
file://0021-Update-syscall-inout-table.patch \
file://0022-Fix-syscall-generator-scripts.patch \
file://0023-syscall-inout-table-fix-old_select-and-old_mmap.patch \
           "

# Use :append here so that the patch is applied also when using devupstream
SRC_URI:append = " file://0001-src-Kbuild-change-missing-CONFIG_TRACEPOINTS-to-warn.patch"

SRC_URI[sha256sum] = "bf808b113544287cfe837a6382887fa66354ef5cc8216460cebbef3d27dc3581"

export INSTALL_MOD_DIR="kernel/lttng-modules"

EXTRA_OEMAKE += "KERNELDIR='${STAGING_KERNEL_DIR}'"

MODULES_MODULE_SYMVERS_LOCATION = "src"

do_install:append() {
	# Delete empty directories to avoid QA failures if no modules were built
	if [ -d ${D}/${nonarch_base_libdir} ]; then
		find ${D}/${nonarch_base_libdir} -depth -type d -empty -exec rmdir {} \;
	fi
}

python do_package:prepend() {
    if not os.path.exists(os.path.join(d.getVar('D'), d.getVar('nonarch_base_libdir')[1:], 'modules')):
        bb.warn("%s: no modules were created; this may be due to CONFIG_TRACEPOINTS not being enabled in your kernel." % d.getVar('PN'))
}

BBCLASSEXTEND = "devupstream:target"
SRC_URI:class-devupstream = "git://git.lttng.org/lttng-modules;branch=stable-2.13;protocol=https"
SRCREV:class-devupstream = "7584cfc04914cb0842a986e9808686858b9c8630"
SRCREV_FORMAT ?= "lttng_git"
