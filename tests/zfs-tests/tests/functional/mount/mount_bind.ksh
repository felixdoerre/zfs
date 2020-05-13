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

bind=$TESTDIR.bind
fs=$TESTPOOL/$TESTFS.bind

log_must mkdir -p ${bind}1
log_must mkdir -p ${bind}2
log_must zfs create -o mountpoint=${bind}1 $fs

function cleanup {
    zfs destroy -r "$fs"
}

log_onexit cleanup

log_must touch ${bind}1/testfile
log_must zfs snap ${fs}@snap


log_must mount --bind ${bind}1 ${bind}2

log_must ls ${bind}1/.zfs/snapshot/snap/testfile
log_must ls ${bind}2/.zfs/snapshot/snap/testfile
log_must eval "mount | grep @"
log_must umount ${bind}1/.zfs/snapshot/snap
log_mustnot eval "mount | grep @"

log_must ls ${bind}2/.zfs/snapshot/snap/testfile
log_must ls ${bind}1/.zfs/snapshot/snap/testfile
log_must eval "mount | grep @"
log_must umount ${bind}1/.zfs/snapshot/snap
log_mustnot eval "mount | grep @"

log_must umount ${bind}1
log_mustnot ls ${bind}1/.zfs/snapshot/snap/testfile
log_must ls ${bind}2/.zfs/snapshot/snap/testfile
log_must eval "mount | grep @"
log_must umount ${bind}2/.zfs/snapshot/snap
log_mustnot eval "mount | grep @"

log_must umount ${bind}2
# Re-setup for a new scenario
log_must zfs mount ${fs}
log_must mount --bind --make-private ${bind}1 ${bind}2

log_must ls ${bind}2/.zfs/snapshot/snap/testfile
# TODO this currently is a limitation, but not desired
log_mustnot ls ${bind}1/.zfs/snapshot/snap/testfile

log_must umount ${bind}2/.zfs/snapshot/snap
log_mustnot eval "mount | grep @"

# And symmetric
log_must ls ${bind}1/.zfs/snapshot/snap/testfile
# TODO this currently is a limitation, but not desired
log_mustnot ls ${bind}2/.zfs/snapshot/snap/testfile
log_must umount ${bind}1/.zfs/snapshot/snap
log_mustnot eval "mount | grep @"

log_must zfs destroy ${fs}@snap

log_pass "All ZFS file systems would have been unmounted"
