#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Windows DPAPI user's MasterKeys decryption utility."""

import hashlib
import optparse
import os
import sys

try:
    from DPAPI.Core import *
except ImportError:
    raise ImportError('Missing dpapick, install it or set PYTHONPATH.')


def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not options.sid:
        sys.exit('You must provide the user\'s SID textual string.')
    if not options.password and not options.pwdhash:
        sys.exit(
            'You must provide the user password or the user password hash. '
            'The user password hash is the SHA1(UTF_LE(password)), and must '
            'be provided as the hex textual string.')
    if not args:
        sys.exit('You must provide at least one MasterKey file.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] MKfile1 MKfile2 etc.\n\n'
        'It tries to unlock (decrypt) *user* MasterKey files provided.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    for arg in args:
        print ''
        with open(arg, 'rb') as f:
            print 'Working on MK %s\n-------------' % os.path.basename(arg)
            mk = masterkey.MasterKeyFile(f.read())
            if options.password:
                mk.decryptWithPassword(options.sid, options.password)
            elif options.pwdhash:
                mk.decryptWithHash(options.sid, options.pwdhash.decode('hex'))
            else:
                pass

            if mk.decrypted:
                print 'MASTER KEY UNLOCKED!'
                mkey = mk.get_key()
                print 'KEY: %s' % mkey.encode('hex')
                print 'SHA1: %s' % hashlib.sha1(mkey).digest().encode('hex')
            else:
                print 'MK guid: %s' % mk.guid
                print 'UNABLE to UNLOCK master key'
            print ''
