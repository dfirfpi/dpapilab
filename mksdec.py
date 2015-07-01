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
""" Windows DPAPI system's MasterKeys decryption utility."""

import optparse
import os
import re
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
    if not args:
        sys.exit('You must provide at least one MasterKey file.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] MKfile1 MKfile2 etc.\n\n'
        'It tries to unlock (decrypt) *system* MasterKey files provided.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

    mkp = masterkey.MasterKeyPool()
    mkp.addSystemCredential(dpapi_system)

    for arg in args:
        with open(arg, 'rb') as f:
            mkp.addMasterKey(f.read())

    mkp.try_credential_hash(None, None)

    for mkl in mkp.keys.values():
        for mk in mkl:
            print ''
            print 'Working on MK GUID %s\n-------------' % mk.guid
            if mk.decrypted:
                print 'MASTER KEY UNLOCKED!'
                print mk
            else:
                print 'MK guid: %s' % mk.guid
                print 'UNABLE to UNLOCK master key'
            print ''
