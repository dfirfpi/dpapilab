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
""" Windows DPAPI user BLOB decryption utility."""

import optparse
import os
import sys

try:
    from DPAPI.Core import blob
    from DPAPI.Core import masterkey
    from DPAPI.Core import registry
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
    if not args or len(args) != 1:
        sys.exit('You must provide one BLOB file.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] BLOB\n\n'
        'It tries to decrypt a *user* BLOB.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')
    parser.add_option(
        '--hex', default=False, dest='hexencode', action='store_true')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    if options.credhist:
        addCredhistFile(options.sid, options.credhist)

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)

    if options.password:
        mkp.try_credential(options.sid, options.password)
    elif options.pwdhash:
        mkp.try_credential_hash(options.sid, options.pwdhash.decode('hex'))

    blob = blob.DPAPIBlob(open(args[0], 'rb').read())

    mks = mkp.getMasterKeys(blob.mkguid)
    if mks:
        for mk in mks:
            if mk.decrypted:
                blob.decrypt(mk.get_key())
                if blob.decrypted:
                    break
    else:
        print 'MasterKey not found for blob.'

    if blob.decrypted:
            print 'BLOB CLEARTEXT FOLLOWING'
            print '-' * 80
        if options.hexencode:
            print blob.cleartext.encode('hex')
        else:
            print blob.cleartext
        print '-' * 80
    else:
        print 'unable to decrypt blob.'
