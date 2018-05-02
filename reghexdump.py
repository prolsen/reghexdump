'''
The MIT License (MIT)

Copyright (c) 2015 Patrick Olsen

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
'''
import sys, os
import hashlib
import requests
import argparse
from Registry import Registry

def getBinaryEntries(reg, size, write=None, api_key=None, depth=None):
    for subkey in reg.subkeys():
        getBinaryEntries(subkey, size, write, api_key, depth + 1)
        for values in subkey.values():
            try:
                if values.value_type() == Registry.RegBin:
                    if len(values.value()) >= size:
                        binsize = len(values.value())
                        value = values.value()[:128]
                        fullpath = subkey.path() + "\\" + values.name()
                        names = values.name()
                        lastwrite = str(subkey.timestamp()).replace(" ", "T") + "Z"
                        md5hash = hashlib.md5(values.value()).hexdigest()
                        vtresults = getVTResults(md5hash, api_key)
                        vthit = str(md5hash) + " - " + vtresults
                        hexdump = hexdump3(value, 16, 0)
                        
                        if write is not None:
                            #Write out the binary data files.
                            writeData(write, names, value)
                            #Print output
                            getOutput(fullpath, lastwrite, vthit, binsize, hexdump)
                        else:
                            #Print output
                            getOutput(fullpath, lastwrite, vthit, binsize, hexdump)
                            
            except TypeError:
                continue

def getVTResults(md5hash, api_key):
    if api_key is not None:
        params = {'apikey': api_key, 'resource': md5hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = response.json()
        if json_response['response_code'] == 0:
            ratio = "None"
        elif json_response['positives'] >= 1:
            ratio = str(json_response['positives']) + "/" + str(json_response['total'])
        return(ratio)
    else:
        return("None")

#Ref1: http://www.decalage.info/python/ezhexviewer
#Ref2: http://c2.com/cgi/wiki?HexDumpInManyProgrammingLanguages
def hexdump3(src, length=None, startindex=None):
    """
    Returns a hexadecimal dump of a binary string.
    length: number of bytes per row.
    startindex: index of 1st byte.
    """
    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    
    result=[]
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%08X   %-*s   %s\n" % (i+startindex, length*3, hexa, printable))
    return ''.join(result)

def writeData(write, names, value):
    open(os.path.join(write + names), 'wb').write(value)
    
def getOutput(fullpath, lastwrite, vthit, binsize, hexdump):
    print "Path: {0}\nLastWrite: {1}\nMD5: {2}\nSize: {3}\n{4}".format(fullpath, lastwrite, vthit, binsize, hexdump)

def main():    
    parser = argparse.ArgumentParser(description='Parse Registry hive looking for malicious Binary data.')
    parser.add_argument('--hive', 
                        help='Path to Hive.')
    parser.add_argument('--size', 
                        help='Size in bytes.')
    parser.add_argument('--write', 
                        help='Write the binary values out to a directory.')
    parser.add_argument('--virustotal',
                        help='Query VT with data hashes.')
    args = parser.parse_args()

    if args.virustotal:
        api_key = args.virustotal
    else:
        #You can specify a default API key here vs. None.
        api_key = None
        
    if args.write:
        try:
            reg = Registry.Registry(args.hive).root()
            getBinaryEntries(reg, int(args.size), args.write, api_key, depth=0)
        except TypeError:
            pass

if __name__ == "__main__":
    main()
    
