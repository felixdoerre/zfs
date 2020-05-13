#!/bin/ksh -p

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2020 by Felix Dörre. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib

chroot=$TESTDIR.chroot
fs=$TESTPOOL/$TESTFS.chroot

log_must mkdir -p $chroot/dataset
log_must zfs create -o mountpoint=$chroot/dataset $fs

function cleanup {
    zfs destroy -r "$fs"
    rm -R "$chroot"
}

log_onexit cleanup

function test_chroot {
    local mountpoint=$1
    local dir=$2
    local mountpoint_inner=$3

    log_must mkdir -p "$dir/bin"
    log_must cp /bin/busybox "$dir/bin"
    log_must ln -s /bin/busybox "$dir/bin/sh"
    log_must ln -s /bin/busybox "$dir/bin/ls"
    log_must zfs snap ${fs}@snap

    log_must /usr/sbin/chroot ${dir} /bin/ls ${mountpoint_inner}/.zfs/snapshot/snap/bin/busybox
    log_must ls ${mountpoint}/.zfs/snapshot/snap/bin/busybox
    log_must eval "mount | grep @"
    log_must umount ${mountpoint}/.zfs/snapshot/snap
    log_mustnot eval "mount | grep @"

    log_must ls ${mountpoint}/.zfs/snapshot/snap/bin/busybox
    log_must /usr/sbin/chroot ${dir} /bin/ls ${mountpoint_inner}/.zfs/snapshot/snap/bin/busybox
    log_must eval "mount | grep @"

    log_must umount ${mountpoint}/.zfs/snapshot/snap
    log_must zfs destroy ${fs}@snap
}

test_chroot "$chroot/dataset" "$chroot/dataset" ""
test_chroot "$chroot/dataset" "$chroot" "/dataset"

log_pass "All ZFS file systems would have been unmounted"
