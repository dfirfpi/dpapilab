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
""" Windows DPAPI BLOB decryption utility."""

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
    if not options.masterkeydir:
        sys.exit('You must provide a masterkeys directory!')
    if options.sid:
        if not options.password and not options.pwdhash:
            sys.exit('You must provide the user password or password hash!')
    else:
        if not options.security or not options.system:
            sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not args or not len(args) == 1:
        sys.exit('You must provide an argument.')


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] BLOB\n\n'
        'It tries to decrypt a user|system DPAPI encrypted BLOB.'
        'User blob needs sid and password at least.'
        'System blob needs system and security at least.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')
    parser.add_option('--entropy_hex', metavar='HIVE', dest='entropy_hex')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)

    if options.sid:
        if options.credhist:
            mkp.addCredhistFile(options.sid, options.credhist)
        if options.password:
            mkp.try_credential(options.sid, options.password)
        elif options.pwdhash:
            mkp.try_credential_hash(options.sid, options.pwdhash.decode('hex'))
    else:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.security, options.system)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

        mkp.addSystemCredential(dpapi_system)
        mkp.try_credential_hash(None, None)

    blob = blob.DPAPIBlob(open(args[0], 'rb').read())

    mks = mkp.getMasterKeys(blob.mkguid)

    entropy = None
    if options.entropy_hex:
        entropy = options.entropy_hex.decode('hex')

    if len(mks) == 0:
        sys.exit('Unable to find MK for blob %s' % blob.mkguid)

    for mk in mks:
        if mk.decrypted:
            blob.decrypt(mk.get_key(), entropy=entropy)
            if blob.decrypted:
                print 'Blob Decrypted, HEX and TEXT following...'
                print '-' * 79
                print blob.cleartext.encode('hex')
                print '-' * 79
                print blob.cleartext
                print '-' * 79
            else:
                print 'unable to decrypt blob'
        else:
            print 'unable to decrypt master key'
