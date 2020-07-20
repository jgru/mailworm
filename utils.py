import subprocess
import hashlib

ALERT_PFX = "[!] "
NOTE_PFX = "[+] "
IMP_PFX = "[*] "


def print_sep(c=10):
    print(c * "---")


def calc_hash(fp):
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(fp, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)

    return str(hasher.hexdigest())


def exec_cmd(cmd):
    subprocess.call(cmd)

