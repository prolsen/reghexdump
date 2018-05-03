'''
The MIT License (MIT)

Copyright (c) 2018 Patrick Olsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Author: Patrick Olsen
Twitter: @patrickrolsen
'''
import os
import sys
import argparse
import hashlib
from Registry import Registry

class HelperFunctions(object):
    def __init__(self, hive=None):
        self.hive = hive

    def getRoot(self):
        root = Registry.Registry(self.hive).root()
        return(root)

class RegistryStrings(object):
    def __init__(self, binary_size, string_size):
        self.binary_size = binary_size
        self.string_size = string_size

    def getStrings(self, root, depth=0):

        for subkey in root.subkeys():
            # This recurse through the hive.
            self.getStrings(subkey, depth + 1)
            # Enumerating the values with keys and subkeys.
            for values in subkey.values():
                # Only match RegSZ and RegExpandSZ
                if values.value_type() == Registry.RegSZ or \
                    values.value_type() == Registry.RegExpandSZ:
                    # Defining variables
                    value_name = values.name()
                    value_data = values.value()
                    full_path = subkey.path() + "\\" + value_name
                    value_data_text = value_data.encode('utf-8').strip()
                    '''
                    Check if the string is equal or larger than the specifed
                    ssize arguement.
                    '''
                    if int(len(value_data)) >= self.string_size:
                        print str(subkey.timestamp()), 'string', full_path, \
                            value_data_text[0:35]
                    '''
                    If value data ends in = it's assumed to be base64. 
                    If the word, powershell is inside a string it will print
                    that as well.
                    '''
                    if value_data_text.endswith('=') or 'powershell' in value_data_text:
                        print str(subkey.timestamp()), 'string', full_path,  \
                        value_data_text[0:35]

    def getBinary(self, root, depth=0):
        for subkey in root.subkeys():
            # This recurse through the hive.
            self.getBinary(subkey, depth + 1)
            # Enumerating the values with keys and subkeys.
            for values in subkey.values():
                # Only look at RegBins
                if values.value_type() == Registry.RegBin:
                    # Defining variables
                    value_name = values.name()
                    value_data = values.value()
                    full_path = subkey.path() + "\\" + value_name
                    '''
                    This hashes the binary blob of data. I've used this to detect 
                    PE in the registry. Likely not useful for other types of blobs
                    of binary data.
                    '''
                    md5hash = hashlib.md5(values.value()).hexdigest()
                    '''
                    Check if the binary blob is equal or larger than the specifed
                    bsize arguement.
                    '''
                    if len(value_data) >= self.binary_size:
                        print str(subkey.timestamp()), 'binary', full_path, md5hash

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses a registry hive looking fileless malware.')
    parser.add_argument('--hive', required=True, \
        help='Path to Hive.')
    parser.add_argument('-b', '--bsize', required=True, \
        help='Binary size in bytes.')
    parser.add_argument('-s', '--ssize', required=True, \
        help='String size in bytes.')
    args = parser.parse_args()
    
    hive = args.hive
    binary_size = int(args.bsize)
    string_size = int(args.ssize)

    root = HelperFunctions(hive).getRoot()
    '''
    Currently no error handling as i'm still testing at the moment.
    '''
    RegistryStrings(binary_size, string_size).getStrings(root, depth=0)
    RegistryStrings(binary_size, string_size).getBinary(root, depth=0)
