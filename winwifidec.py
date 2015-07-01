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
""" Windows system WiFi password offline and online decryptor."""

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
    if args:
        sys.exit('No arguments required.')
    if not options.security or not options.system:
        sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not options.masterkeydir:
        sys.exit('You must provide the system DPAPI folder, see <usage>.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] *noargs*\n\n'
        'It decrypts Windows WiFi password stored in '
        '<\\ProgramData\\Microsoft\\WwanSvc\\Profiles> files. '
        'You must provide such directory, SYSTEM and SECURITY hives and, '
        'finally, the system DPAPI MasterKeys, stored in '
        '<\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User>.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')
    parser.add_option('--wdir', metavar='WIFIDIR', dest='wifi_dir')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
    mkp.addSystemCredential(dpapi_system)
    mkp.try_credential_hash(None, None)

    for root, _, files in os.walk(options.wifi_dir):
        for file in files:
            filepath = os.path.join(root, file)
            with open(filepath, 'r') as f:
                file_data = f.read().replace('\x0a', '').replace('\x0d', '')
                wifi_name = re.search('<name>([^<]+)</name>', file_data)
                wifi_name = wifi_name.group(1)
                key_material_re = re.search(
                    '<keyMaterial>([0-9A-F]+)</keyMaterial>', file_data)
                if not key_material_re:
                    continue
                key_material = key_material_re.group(1)
                wblob = blob.DPAPIBlob(key_material.decode('hex'))
                wifi_pwd = '<not decrypted>'
                mks = mkp.getMasterKeys(wblob.mkguid)
                for mk in mks:
                    if mk.decrypted:
                        wblob.decrypt(mk.get_key())
                        if wblob.decrypted:
                            wifi_pwd = wblob.cleartext
                        break
                print 'Wifi:{} Password:{}'.format(wifi_name, wifi_pwd)
