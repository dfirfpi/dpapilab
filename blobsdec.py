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
""" Windows DPAPI system BLOB decryption utility."""

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
    if not options.security or not options.system:
        sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not options.masterkeydir:
        sys.exit('You must provide system masterkeys directory.')
    if not args or not len(args) == 1:
        sys.exit('You must provide an argument.')


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] BLOB\n\n'
        'It tries to decrypt a *system* BLOB.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')
    parser.add_option('--hex', default=False, dest='hexencode',
        action='store_true')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
    mkp.addSystemCredential(dpapi_system)
    mkp.try_credential_hash(None, None)

    blob = blob.DPAPIBlob(open(args[0], 'rb').read())

    mks = mkp.getMasterKeys(blob.mkguid)
    for mk in mks:
        if mk.decrypted:
            blob.decrypt(mk.get_key())
            if blob.decrypted:
                if options.hexencode:
                    print 'BLOB CLEARTEXT HEX ENCODED FOLLOWING'
                    print '-' * 79
                    print blob.cleartext.encode('hex')
                    print '-' * 79
                else:
                    print blob.cleartext
            else:
                print 'unable to decrypt blob'
        else:
            print 'unable to decrypt key'
