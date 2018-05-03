# regdump
Searches a registry hive for large string sizes and large binary blobs in an effrot to identify fileless malware among others.

# Help

Play with the sizes a bit. Sizes are in bytes.

python regdump.py -h

    usage: regdump.py [-h] --hive HIVE -b BSIZE -s SSIZE

    Parses a registry hive looking fileless malware.

    optional arguments:
      -h, --help            show this help message and exit
      --hive HIVE           Path to Hive.
      -b BSIZE, --bsize BSIZE
                        Binary size in bytes.
      -s SSIZE, --ssize SSIZE
                        String size in bytes.

# Example

    python regdump.py --hive NTUSER.DAT --ssize 200 --bsize 50000

# reghexdump
Windows Registry parser that outputs values in hex. Also allows searching for a binary blob size.  Contribution settings 

Help
=====
                                python reghexdump.py -h
                                usage: reghexdump.py [-h] [--hive HIVE] [--size SIZE] [--write WRITE]
                                    [--virustotal VIRUSTOTAL]
                                
                                Parse Registry hive looking for malicious Binary data.
                                
                                optional arguments:
                                    -h, --help            show this help message and exit
                                    --hive HIVE           Path to Hive.
                                    --size SIZE           Size in bytes.
                                    --write WRITE         Write the binary values out to a directory.
                                    --virustotal VIRUSTOTAL
                                        Query VT with data hashes.

How to use
==========

                                python reghexdump.py --hive NTUSER.DAT.copy0 --size 20000
                                Path: CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}\Software\ xsw\binaryImage32
                                LastWrite: 2015-04-21T14:17:17.642979Z
                                MD5: 5be923a9a323667dc6ae33fb2f4a80a6 - None
                                Size: 223744
                                00000000   4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
                                00000010   B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
                                00000020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
                                00000030   00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00    ................
                                00000040   0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68    ........!..L.!Th
                                00000050   69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F    is program canno
                                00000060   74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20    t be run in DOS
                                00000070   6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00    mode....$.......
                                
                                Path: CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}\Software\Microsoft\Active Setup\Installed Components\{72507C54-3577-4830-815B-310007F6135A}\Rc4Encoded32
                                LastWrite: 2015-04-21T14:17:26.051649Z
                                MD5: 26ef08eb9dd49c53e0526bf148d23e3d - None
                                Size: 54669
                                00000000   87 87 3F 5C D1 25 67 7D C8 47 0F 5A 9C B7 D1 3E    ..?..%g}.G.Z...>
                                00000010   0B 34 AB 0E 9D 2E 59 D6 A2 51 C7 66 18 54 5A C2    .4....Y..Q.f.TZ.
                                00000020   1D 6B C0 B8 17 F6 23 C3 7D CA B2 2F E3 10 82 5A    .k....#.}../...Z
                                00000030   C8 99 9C 83 C9 4C 58 FB C7 FC 14 3E 15 9C B4 70    .....LX....>...p
                                00000040   82 3B 35 AF E3 B9 B2 E3 34 47 7F 50 46 74 01 B6    .;5.....4G.PFt..
                                00000050   F2 72 D1 76 44 71 B2 F5 82 21 F6 79 0F FE EE 68    .r.vDq...!.y...h
                                00000060   CE 04 8E 0F 51 2D C3 FE 70 BC 78 BC 2C 6E 94 1D    ....Q-..p.x.,n..
                                00000070   E9 0C 40 C5 98 DD 2F 09 2D 27 7E 14 B6 DA 28 3C    ..@.../.-'~...(<
