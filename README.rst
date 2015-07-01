=================
Windows DPAPI lab
=================

My own DPAPI laboratory. Here I put some ongoing works that involve Windows
DPAPI (Data Protection API). It's a lab, so something could not work: please 
see "How to Use".

How to use
----------

Every utility has usually a minimal description that should help its usage.
Please consider that this is a *laboratory*, so don't expect that everything
will work: there are experiments and messy stuffs here. Usually I create a
brief description (as the followings) for those utilities that are completed.

In any case feel free to open a bug or a request. Any contribution is much 
appreciated.

There is one major dependency in almost every utility or script: **dpapick**.
You can install it using *pip* or manually after you have downloaded the
package from https://bitbucket.org/jmichel/dpapick. Since I sometimes change
dpapick, I did not install it and, when in need, I set then environment 
variable *PYTHONPATH*.

**blobinfo.py**: this small utility simply tries to parse a DPAPI BLOB file.

**blobsdec.py**: this utility tries to unlock (decrypt) a *system* DPAPI BLOB
file provided, using DPAPI system key stored in LSA secrets.

**blobudec.py**: this utility tries to unlock (decrypt) the *user* DPAPI BLOB
file provided, using the user password or password hash.

**mkinfo.py**: this small utility simply tries to parse a MasterKey file or a
directory containing MasterKey files.

**mksdec.py**: this utility tries to unlock (decrypt) the *system* MasterKey
files provided, using DPAPI system key stored in LSA secrets.

**mkudec.py**: this utility tries to unlock (decrypt) the *user* MasterKey files
provided, using the user password or password hash.

**winwifidec.py**: this utility (formerly called wiffy.py) decrypts Windows WiFi
password. These credentials are (usually) system wide, so the OS is able to 
decrypt it even  when no users are logged in. To decrypt them you need: the 
DPAPI system key, which is one of the OS LSA secrets; the system MasterKeys, 
stored in  ``\Windows\System32\Microsoft\Protect\S-1-5-18\User``; the WiFi xml 
files' directory,  ``\ProgramData\Microsoft\WwanSvc\Profiles``.

Licensing and Copyright
-----------------------

Copyright 2015 Francesco "dfirfpi" Picasso. All Rights Reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

Bugs and Support
----------------

There is no support provided with this software. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

For any bug or enhancement please use this site facilities.
