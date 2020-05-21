#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

. $STF_SUITE/include/libtest.shlib

ls -als "$TESTDIR"

username="$(id -un)"

function keystatus {
    log_must [ "$(zfs list -Ho keystatus "$TESTPOOL/pam/${username}")" == "$1" ]
}

function genconfig {
    for i in password auth session; do
	printf "%s\trequired\tpam_permit.so\n%s\toptional\tpam_zfs_key.so\t%s\n" "$i" "$i" "$1"
    done > /etc/pam.d/pam_zfs_key_test
}

function references {
    log_must [ "$(cat "/var/run/pam_zfs_key/$(id -u ${username})")" == "$1" ]
}

function mounted {
    assert $(mount | grep -F "$TESTPOOL/pam/${username} on " | wc -l) == $1
}

echo "testpass" | zfs create -o encryption=aes-256-gcm -o keyformat=passphrase -o keylocation=prompt "$TESTPOOL/pam/${username}"
mounted 1
keystatus available
log_must zfs unmount "$TESTPOOL/pam/${username}"
log_must zfs unload-key "$TESTPOOL/pam/${username}"
mounted 0
keystatus unavailable

genconfig "homes=$TESTPOOL/pam"
echo "testpass" | /usr/bin/pamtester pam_zfs_key_test ${username} open_session
references 1
mounted 1
keystatus available

echo "testpass" | /usr/bin/pamtester pam_zfs_key_test ${username} open_session
references 2
mounted 1
keystatus available

log_must /usr/bin/pamtester pam_zfs_key_test ${username} close_session
references 1
mounted 1
keystatus available

log_must /usr/bin/pamtester pam_zfs_key_test ${username} close_session
references 0
mounted 0
keystatus unavailable

genconfig "homes=$TESTPOOL/pam nounmount"
echo "testpass" | /usr/bin/pamtester pam_zfs_key_test ${username} open_session
references 1
mounted 1
keystatus available

echo "testpass" | /usr/bin/pamtester pam_zfs_key_test ${username} open_session
references 2
keystatus available
mounted 1

log_must /usr/bin/pamtester pam_zfs_key_test ${username} close_session
references 1
keystatus available
mounted 1

log_must /usr/bin/pamtester pam_zfs_key_test ${username} close_session
references 0
keystatus available
mounted 1

log_pass "done."
