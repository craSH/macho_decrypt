#!/usr/bin/env python
"""
FIXME
Copyleft 2013 Ian Gallagher <crash@neg9.org>
"""
import sys, os, struct, mmap, subprocess

def lipo_macho(fname, arch="armv7"):
    out_file = fname + ".patched"
    subprocess.call("lipo -thin {arch} -output {out_file} {fname}".format(**locals()), shell=True)
    return(out_file)

def main():
    import optparse
    parser = optparse.OptionParser(usage="Usage: %prog [options] MachO_file MachO_decrypted_segment cryptoff cryptsize")

    parser.add_option('-d', '--debug', dest='debug', type='int', default=1, help='Debug level (0, 1, 2; default 1)')

    (options, args) = parser.parse_args()

    if len(args) < 4:
        parser.print_usage()
        return(1)

    fname = args[0]
    decrypted_segment = args[1]
    lc_enc_info = struct.pack("<I", 0x21)
    cmdsize = struct.pack("<I", 20)
    _cryptoff = int(args[2])
    cryptoff = struct.pack("<I", _cryptoff)
    _cryptsize = int(args[3])
    cryptsize = struct.pack("<I", _cryptsize)
    cryptid = struct.pack("<I", 1)

    search_block = lc_enc_info + cmdsize + cryptoff + cryptsize

    enc_cmd_offset = -1

    thin_fname = lipo_macho(fname)

    with open(thin_fname, "r+b") as fh:
	mm = mmap.mmap(fh.fileno(), 0)

        # Patch the binary with the decrypted memory dump
        decrypted_bytes = open(decrypted_segment, "rb").read()
        mm.seek(_cryptoff)
        mm.write(decrypted_bytes)
        print("Wrote {0:d} bytes from {1:s} to {2:s} at offset {3:d} to {4:d}".format(len(decrypted_bytes), decrypted_segment, thin_fname, _cryptoff, mm.tell()))

        # Seek back to 0
        mm.seek(0)

        # Find the Encryption Info Load Command
        enc_cmd_offset = mm.find(search_block)

        if enc_cmd_offset != -1:
            print("Found LC_ENCRYPTION_INFO command at byte offset {0:d} (0x{0:x})".format(enc_cmd_offset))
        else:
            print("Didn't find LC_ENCRYPTION_INFO command in {0:s} - aborting.".format(fname))
            return(2)

        # Seek to the beginning of the cryptid field
        mm.seek(enc_cmd_offset + (4 * 4))
        # Read the cryptid
        _cryptid = struct.unpack("<I", mm.read(4))[0]

        if 1 == _cryptid:
            # Seek back 4 bytes (as we read the value above)
            mm.seek(-4, os.SEEK_CUR)
            # Patch it with cryptid set to 0
            mm.write(struct.pack("<I", 0))
            mm.close()
            print("Wrote 0x00000000 (\"no encryption\") at offset {0:d} (0x{0:x})".format(enc_cmd_offset + (4 * 4)))
            print("Successfully patched binary: {0:s}".format(thin_fname))
        elif 0 == _cryptid:
            print("LC_ENCRYPTION_INFO cryptid field is 0x000000 - file {0:s} already marked as non-encrypted, exiting.".format(fname))
            return(0)
        else:
            print("LC_ENCRYPTION_INFO cryptid field is unknown ({0:x} - should be 0x00 or 0x01) - aborting.".format(_cryptid))
            return(2)


    return(0)

if '__main__' == __name__:
    sys.exit(main())

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
