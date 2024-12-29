#!/usr/bin/python3
# (C) Kirils Solovjovs, 2015 - tribit()
#     Leonid Evdokimov, 2024 - /proc archive

import base64, errno, io, os, re, stat, struct, sys, zlib

#            111111 11112222
# 01234567 89012345 67890123
# cdefgh56 78abGH12 34ABCDEF  (from)
# abcdefgh 12345678 ABCDEFGH  (to)
# revtribitmap=[2,3,4,5,6,7,12,13,14,15,0,1,22,23,8,9,10,11,16,17,18,19,20,21]
TRIBITMAP = [
    10, 11,  0 , 1,  2,  3,  4,  5,
    14, 15, 16, 17,  6,  7,  8,  9,
    18, 19, 20, 21, 22, 23, 12, 13,
]


def tribit(content: bytes):
    out = bytes()
    for i in range(0, len(content) - 1, 3):
        raw = content[i : i + 3]
        good = 0
        bad = raw[0] * 0x10000 + raw[1] * 0x100 + raw[2]
        for shift in TRIBITMAP:
            good = (good << 1) + (1 if (bad & (0x800000 >> shift)) else 0)
        out += bytes([(good >> 16) & 0xFF, (good >> 8) & 0xFF, good & 0xFF])
    return out


U32BE = struct.Struct(">I")
U32LE = struct.Struct("<I")


def itlv(fd, U32):
    for tag in iter(lambda: fd.read(1), b""):
        tag = int(tag[0])
        length = U32.unpack(fd.read(U32.size))[0]
        value = fd.read(length)
        assert length == len(value), (length, len(value))
        yield (tag, value)


def mksubdir(prefix, tree):
    dest = os.path.realpath(os.path.join(prefix, *tree))
    if not dest.startswith(prefix + os.path.sep):
        raise RuntimeError("Directory escape?", dest, prefix, tree)
    os.mkdir(dest)


def opensub(prefix, tree, *args, **kwargs):
    dest = os.path.realpath(os.path.join(prefix, *tree))
    if not dest.startswith(prefix + os.path.sep):
        raise RuntimeError("Directory escape?", dest, prefix, tree)
    return open(dest, *args, **kwargs)


def parse_ar(prefix, blob, U32):
    STAT, FNAME, DATA, MAGIC, END = 1, 2, 3, 4, 5  # END is both EOF & `..'
    prefix += "_contents"
    os.mkdir(prefix)

    it = itlv(io.BytesIO(blob), U32)
    t, v = next(it)
    assert t == MAGIC and len(v) == U32.size and U32.unpack(v)[0] == 2, (t, v)
    tree = []
    for t, v in it:
        if t == END:
            assert not v and len(tree) > 0, (v, tree)
            tree.pop()
            continue

        assert t == FNAME, t
        fname = v.decode("ascii")

        t, v = next(it)
        if t == END and len(v) == U32.size:
            fname = os.path.join(*tree, fname)
            err = U32.unpack(v)[0]
            errorcode = errno.errorcode.get(err)
            print("==> ?????????? {:s} !!!! errno={:d} (maybe {:s})".format(fname, err, errorcode))
            continue
        assert t == STAT and len(v) == U32.size, (t, len(v), fname)
        st_stat = U32.unpack(v)[0]
        print("==> {:s} {:s}".format(stat.filemode(st_stat), os.path.join(*tree, fname)), end="")
        fmt, mode = stat.S_IFMT(st_stat), stat.S_IMODE(st_stat)

        if fmt == stat.S_IFDIR:
            tree.append(fname)
            mksubdir(prefix, tree)  # mode is ignored as one needs +w to create stuff :-)
        elif fmt in (stat.S_IFREG, stat.S_IFLNK):
            t, v = next(it)
            with opensub(prefix, tree + [fname], "wb") as dfd:
                while t == DATA:
                    if fmt == stat.S_IFLNK:
                        dfd.write(b"linkto: ")
                    dfd.write(v)
                    t, v = next(it)
            assert t == END and len(v) in (0, U32.size), (t, len(v))
            if len(v) == U32.size:
                err = U32.unpack(v)[0]
                print(" !!!! errno={:d} (maybe {:s})".format(err, errno.errorcode.get(err)), end="")
        else:
            raise NotImplementedError("Unsupported S_IF*", fmt)
        print("")


def main():
    if len(sys.argv) == 3:
        dir = sys.argv[2]
    elif len(sys.argv) == 2:
        dir = sys.argv[1] + "_contents"
    else:
        raise Exception("Usage: {:s} <supout.rif> [output_folder]".format(sys.argv[0]))

    if not os.access(sys.argv[1], os.R_OK):
        raise Exception("Can't read file " + sys.argv[1])
    if not os.path.exists(dir):
        os.makedirs(dir)
    dir = os.path.realpath(dir)
    if not os.access(dir, os.W_OK):
        raise Exception("Directory " + dir + " not writeable")
    if os.listdir(dir) != []:
        raise Exception("Directory " + dir + " not empty")

    with open(sys.argv[1], "r") as supout:
        sections = (
            supout.read()
            .replace("--END ROUTEROS SUPOUT SECTION", "")
            .split("--BEGIN ROUTEROS SUPOUT SECTION")
        )
        i = 0
        for sect in sections:
            sect = "".join(sect.strip().split()).replace("=", "A")
            if not sect:
                continue
            i += 1
            secraw = tribit(base64.b64decode(sect))
            name, blob = secraw.split(b"\x00", 1)
            name = name.decode("ascii")
            print("{:02d} {:6.1f} KiB(z) {:25s}".format(i, len(blob) / 1024, name), end="")
            blob = zlib.decompress(blob)
            oname = "{:02d}_{:s}".format(i, re.sub("[^-._a-zA-Z0-9]", "#", name))
            print(" -> {:6.1f} KiB(raw) {:s}".format(len(blob) / 1024, oname), end="")
            ofull = os.path.join(dir, oname)
            with opensub(dir, (oname,), "wb") as fo:
                fo.write(blob)
            if blob.startswith(b"\4\4\0\0\0\2\0\0\0"):
                print(", archive{LE}")
                parse_ar(ofull, blob, U32LE)
            elif blob.startswith(b"\4\0\0\0\4\0\0\0\2"):
                print(", archive{BE}")
                parse_ar(ofull, blob, U32BE)
            else:
                print("")


if __name__ == "__main__":
    main()
