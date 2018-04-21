  * **nacho.sh** - Shell script to be ran on a Jailbroken iPhone that extracts decrypted segment of a MachO binary's instructions to a file.
    * Usage: ./nacho.sh EncryptedBinary DecryptedSegmentToWrite.bin
  * **macho_patch_nocrypt.py** - Patch an original (thin) MachO binary with decrypted segments, and alter LC_ENCRYPTION_INFO to indicate it is not encrypted.
    * Usage: python macho_patch_nocrypt.py UniKey.patched `[cryptoff from nacho.sh]` `[cryptsize from nacho.sh]`
