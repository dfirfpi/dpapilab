#!/usr/bin/env python

# ############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## This document is the property of Cassidian SAS, it may not be copied or ##
## circulated without prior licence                                        ##
##                                                                         ##
##  Author: Jean-Michel Picod <jmichel.p@gmail.com>                        ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from DPAPI.Core import registry
import sys
from datetime import datetime
from optparse import OptionParser


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--system", metavar="HIVE", dest="system")
    parser.add_option("--security", metavar="HIVE", dest="security")
    parser.add_option("--secret", metavar="NAME", dest="secret")
    parser.add_option("--hex", default=False, dest="hexencode", action="store_true")

    (options, args) = parser.parse_args()

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    if options.secret is not None:
        if secrets.get(options.secret) is not None:
            if options.hexencode:
                print secrets[options.secret]["CurrVal"].encode('hex')
                print secrets[options.secret]["OldVal"].encode('hex')
            else:
                print secrets[options.secret]["CurrVal"]
                print secrets[options.secret]["OldVal"]
    else:
        for i in secrets.keys():
            for k, v in secrets[i].iteritems():
                if k in ("CurrVal", "OldVal"):
                    print "\t".join([i, k, v.encode('hex') if options.hexencode else v])
                elif k in ("OupdTime", "CupdTime"):
                    print "\t".join([i, k, datetime.utcfromtimestamp(v).isoformat(" ")])

# vim:ts=4:expandtab:sw=4

