#!/usr/bin/env python3
"""
chkdsk_rescue.py - recover NTFS files that CHKDSK "fixed" into oblivion.

When CHKDSK finds a corrupt $ATTRIBUTE_LIST it deletes it, then deletes the
file's extension MFT records as "orphan file record segments" and frees their
clusters. The file is left truncated (often 0 bytes), but the freed extension
records usually still hold the run lists, each stamped with the base record
number. This tool finds them, rebuilds the files, and extracts them.

Read-only against the source. Python 3 standard library only.

USAGE
  Scan (auto-detects damaged files, no log needed):
    python3 chkdsk_rescue.py /dev/sdX2 --out /mnt/target/rescue
  Use a CHKDSK log (Event Viewer text) to pick targets:
    python3 chkdsk_rescue.py H.img --log chkdsk_1001.txt --out ...
  Specific base records (hex, as CHKDSK prints them):
    python3 chkdsk_rescue.py H.img --records DB28 DB2D --out ...
  Explain gaps (and recover pieces where possible) by finding old attribute lists:
    ... --deep                 (reads the volume's free space; slower)
  Extract everything found, or a selection:
    ... --extract              (all)
    ... --extract DB28,DB2D    (selected)
    ... --extract --keep-paths (recreate original folder structure)

  Source can be a partition device, a partition image, or a whole-disk image
  (NTFS partitions are listed; rerun with --offset).

  BitLocker volumes: unlock read-only with cryptsetup first and point the tool
  at /dev/mapper/<name>; the tool detects BitLocker and prints the steps.

  ALWAYS write --out to a different disk than the source. On a live device,
  `blockdev --setro /dev/sdX` first.
"""
import argparse, json, os, re, stat, struct, sys
from collections import defaultdict

ATTR_LIST, ATTR_FN, ATTR_DATA, ATTR_END = 0x20, 0x30, 0x80, 0xFFFFFFFF
ROOT = 5
MASK48 = (1 << 48) - 1


def eprint(*a):
    print(*a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- NTFS

class NTFS:
    def __init__(self, path, offset=0):
        self.path, self.offset = path, offset
        self.fd = os.open(path, os.O_RDONLY)
        bs = self.read(0, 512)
        if bs[3:11] != b"NTFS    ":
            raise ValueError("no NTFS boot sector")
        self.bps = struct.unpack_from("<H", bs, 0x0B)[0]
        spc = bs[0x0D]
        spc = 1 << (256 - spc) if spc > 0x80 else spc
        self.cluster = self.bps * spc
        self.total_clusters = struct.unpack_from("<Q", bs, 0x28)[0] // spc
        self.mft_lcn = struct.unpack_from("<Q", bs, 0x30)[0]
        cpr = struct.unpack_from("<b", bs, 0x40)[0]
        self.rec_size = (1 << -cpr) if cpr < 0 else cpr * self.cluster
        self.mft_runs = self._load_mft_runs()
        self._bitmap = None

    def read(self, off, n):
        return os.pread(self.fd, n, self.offset + off)

    def fixup(self, rec):
        try:
            usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
        except struct.error:
            return rec, True
        rec, torn = bytearray(rec), False
        if usa_off + 2 * usa_cnt > len(rec):
            return bytes(rec), True
        usn = bytes(rec[usa_off:usa_off + 2])
        for i in range(1, usa_cnt):
            end = i * self.bps - 2
            if end + 2 > len(rec):
                break
            if rec[end:end + 2] != usn:
                torn = True
            rec[end:end + 2] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
        return bytes(rec), torn

    def _rec_at(self, runs, n):
        byte = n * self.rec_size
        for vcn, ln, lcn in runs:
            if lcn is not None and vcn * self.cluster <= byte < (vcn + ln) * self.cluster:
                return self.read(lcn * self.cluster + byte - vcn * self.cluster, self.rec_size)
        return None

    def _load_mft_runs(self):
        raw = self.read(self.mft_lcn * self.cluster, self.rec_size)
        if raw[:4] != b"FILE":
            raise ValueError("$MFT record 0 not found where the boot sector says")
        rec, _ = self.fixup(raw)
        runs, alist = [], None
        for a in parse_attrs(rec):
            if a["type"] == ATTR_DATA and a["name_len"] == 0 and a["nonres"]:
                runs += decode_runs(rec, a)
            elif a["type"] == ATTR_LIST:
                alist = a
        if alist is not None:  # $MFT itself fragmented across extension records
            body = alist["content"] if not alist["nonres"] else self._read_nonres(rec, alist)
            for e in parse_attr_list(body):
                if e["type"] == ATTR_DATA and e["rec"] != 0:
                    raw2 = self._rec_at(sorted(runs), e["rec"])
                    if raw2 and raw2[:4] == b"FILE":
                        r2, _ = self.fixup(raw2)
                        for a in parse_attrs(r2):
                            if a["type"] == ATTR_DATA and a["name_len"] == 0 and a["nonres"]:
                                runs += decode_runs(r2, a)
        return sorted(set(runs))

    def _read_nonres(self, rec, a):
        out = bytearray()
        for vcn, ln, lcn in decode_runs(rec, a):
            out += b"\0" * (ln * self.cluster) if lcn is None else self.read(lcn * self.cluster, ln * self.cluster)
        return bytes(out[:a["real"]])

    def record_count(self):
        return sum(ln for _, ln, _ in self.mft_runs) * self.cluster // self.rec_size

    def read_record(self, n):
        raw = self._rec_at(self.mft_runs, n)
        if not raw or raw[:4] != b"FILE":
            return None
        return self.fixup(raw)[0]

    def iter_records(self):
        per = self.cluster / self.rec_size
        recno = 0
        for vcn, ln, lcn in self.mft_runs:
            recno = int(vcn * per)
            if lcn is None:
                continue
            off, left = lcn * self.cluster, ln * self.cluster
            while left > 0:
                chunk = self.read(off, min(left, 32 << 20))
                if not chunk:
                    return
                for i in range(0, len(chunk) - self.rec_size + 1, self.rec_size):
                    yield recno, chunk[i:i + self.rec_size]
                    recno += 1
                off += len(chunk)
                left -= len(chunk)

    def bitmap(self):
        if self._bitmap is None:
            rec = self.read_record(6)
            for a in parse_attrs(rec):
                if a["type"] == ATTR_DATA and a["name_len"] == 0:
                    self._bitmap = a["content"] if not a["nonres"] else self._read_nonres(rec, a)
                    break
        return self._bitmap

    def count_in_use(self, lcn, length):
        """Clusters in [lcn, lcn+length) currently marked allocated."""
        bm, total, pos, end = self.bitmap(), 0, lcn, lcn + length
        while pos < end:
            step = min(end - pos, 8 << 20)
            b0, b1 = pos >> 3, (pos + step + 7) >> 3
            v = int.from_bytes(bm[b0:b1], "little") >> (pos & 7)
            total += (v & ((1 << step) - 1)).bit_count()
            pos += step
        return total


def parse_attrs(rec):
    try:
        off = struct.unpack_from("<H", rec, 0x14)[0]
        used = min(struct.unpack_from("<I", rec, 0x18)[0], len(rec))
    except struct.error:
        return
    while off + 16 <= used:
        atype, alen = struct.unpack_from("<II", rec, off)
        if atype == ATTR_END or alen < 16 or off + alen > len(rec):
            return
        a = {"type": atype, "off": off, "len": alen, "nonres": rec[off + 8],
             "name_len": rec[off + 9], "flags": struct.unpack_from("<H", rec, off + 0x0C)[0]}
        if a["nonres"]:
            if alen < 0x40:
                return
            a["start"], a["last"], a["run_off"], a["cu"] = struct.unpack_from("<QQHH", rec, off + 0x10)
            a["alloc"], a["real"], a["init"] = struct.unpack_from("<QQQ", rec, off + 0x28)
        else:
            clen, coff = struct.unpack_from("<IH", rec, off + 0x10)
            a["content"] = rec[off + coff:off + coff + clen]
        yield a
        off += alen


def decode_runs(rec, a):
    p, end = a["off"] + a["run_off"], a["off"] + a["len"]
    vcn, lcn, out = a["start"], 0, []
    while p < end and rec[p] != 0:
        h = rec[p]; ln, lo = h & 0x0F, h >> 4; p += 1
        if ln == 0 or p + ln + lo > end:
            raise ValueError("bad runlist")
        length = int.from_bytes(rec[p:p + ln], "little"); p += ln
        if lo:
            lcn += int.from_bytes(rec[p:p + lo], "little", signed=True); p += lo
            out.append((vcn, length, lcn))
        else:
            out.append((vcn, length, None))
        vcn += length
    return out


def parse_attr_list(body):
    out, p = [], 0
    while p + 0x1A <= len(body):
        atype, elen = struct.unpack_from("<IH", body, p)
        if elen == 0:
            break
        start_vcn, ref = struct.unpack_from("<QQ", body, p + 8)
        out.append({"type": atype, "start": start_vcn, "rec": ref & MASK48})
        p += elen
    return out


def file_names(rec):
    """[(parent_rec, name, namespace)] from resident $FILE_NAME attributes."""
    out = []
    for a in parse_attrs(rec):
        if a["type"] == ATTR_FN and not a["nonres"] and len(a["content"]) >= 0x42:
            c = a["content"]
            n = c[0x40]
            out.append((struct.unpack_from("<Q", c, 0)[0] & MASK48, c[0x42:0x42 + 2 * n].decode("utf-16le", "replace"), c[0x41]))
    return out


def best_name(fns):
    if not fns:
        return None
    return sorted(fns, key=lambda f: f[2] == 2)[0]  # prefer anything over DOS 8.3


# ------------------------------------------------------------------ partitions

SIGS = {b"NTFS    ": "NTFS", b"-FVE-FS-": "BitLocker"}


def volume_kind(path, offset=0):
    fd = os.open(path, os.O_RDONLY)
    try:
        return SIGS.get(os.pread(fd, 8, offset + 3))
    finally:
        os.close(fd)


def find_ntfs_partitions(path):
    """[(partition_number, byte_offset, 'NTFS' | 'BitLocker')] on a whole disk."""
    fd = os.open(path, os.O_RDONLY)
    rd = lambda off, n: os.pread(fd, n, off)
    found = []
    try:
        hdr = rd(512, 512)
        if hdr[:8] == b"EFI PART":
            ent_lba, count, size = struct.unpack_from("<QII", hdr, 0x48)
            tbl = rd(ent_lba * 512, count * size)
            starts = [(i + 1, struct.unpack_from("<Q", tbl, i * size + 0x20)[0]) for i in range(count)]
        else:
            mbr = rd(0, 512)
            starts = []
            if mbr[510:512] == b"\x55\xaa":
                starts = [(i + 1, struct.unpack_from("<I", mbr, 0x1BE + 16 * i + 8)[0]) for i in range(4)]
        for n, lba in starts:
            kind = SIGS.get(rd(lba * 512 + 3, 8)) if lba else None
            if kind:
                found.append((n, lba * 512, kind))
    finally:
        os.close(fd)
    return found


BITLOCKER_HELP = """\
{src} is BitLocker-encrypted. Unlock it read-only first, then point this tool
at the unlocked view (needs cryptsetup 2.3+; you will be asked for the
password or the 48-digit recovery key):

  cryptsetup bitlkDump {dev}
  cryptsetup open --type bitlk --readonly {dev} unlocked
  python3 {prog} /dev/mapper/unlocked --out /path/on/another/disk ...
  cryptsetup close unlocked

If the drive normally unlocks automatically (TPM), use the recovery key: it is
usually saved in the owner's Microsoft account, or held by the IT department.
If cryptsetup rejects the volume, dislocker is an alternative.{extra}"""


# ------------------------------------------------------------------ devices

def _sysfs_leaves(devnum):
    """Partitions/disks at the bottom of a block device's stack (follows
    device-mapper, LUKS, BitLocker, md via sysfs 'slaves'). Returns a set of
    (leaf_name, whole_disk_name); empty if not a real block device."""
    try:
        p = os.path.realpath(f"/sys/dev/block/{os.major(devnum)}:{os.minor(devnum)}")
    except (OSError, ValueError):
        return set()
    if not os.path.isdir(p):
        return set()
    out, stack, seen = set(), [p], set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        slaves = os.path.join(cur, "slaves")
        kids = os.listdir(slaves) if os.path.isdir(slaves) else []
        if kids:
            stack += [os.path.realpath(os.path.join(slaves, k)) for k in kids]
            continue
        disk = os.path.dirname(cur) if os.path.exists(os.path.join(cur, "partition")) else cur
        out.add((os.path.basename(cur), os.path.basename(disk)))
    return out


def check_output_location(src_stat, out_dir):
    """Refuse output on the same partition as a block-device source; warn if
    it is merely another partition of the same physical disk."""
    if not stat.S_ISBLK(src_stat.st_mode):
        return  # an image file: writing next to it is fine
    src = _sysfs_leaves(src_stat.st_rdev)
    dst = _sysfs_leaves(os.stat(out_dir).st_dev)
    if not src or not dst:
        if not dst:
            eprint("note: could not determine which disk --out lives on; make sure it is not the source disk")
        return
    dst_disks = {d for _, d in dst}
    whole_disk_src = any(l == d and d in dst_disks for l, d in src)  # source is a whole disk
    if whole_disk_src or {l for l, _ in src} & {l for l, _ in dst}:
        sys.exit("error: --out is on the volume being recovered (directly or through an "
                 "encryption/mapper layer). Write to a different disk.")
    if {d for _, d in src} & {d for _, d in dst}:
        eprint("WARNING: --out is on another partition of the same physical disk as the source. "
               "That does not overwrite the source, but a separate disk is safer.")


# ------------------------------------------------------------------------ scan

def read_text_any(path):
    """Windows tools often write UTF-16 (PowerShell Out-File, Event Viewer exports)."""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace")
    sample = raw[:4096]
    if sample and sample.count(0) > len(sample) // 4:  # BOM-less UTF-16
        return raw.decode("utf-16-le" if sample[1::2].count(0) > sample[0::2].count(0) else "utf-16-be",
                          errors="replace")
    return raw.decode("utf-8", errors="replace")


def parse_log(path):
    text = read_text_any(path)
    bases = {int(h, 16) for h in re.findall(r"\bfile (?:0x)?([0-9A-Fa-f]+)\b", text)}
    orphans = {int(h, 16) for h in re.findall(r"file record segment (?:0x)?([0-9A-Fa-f]+)", text, re.I)}
    return bases, orphans


def scan(vol, explicit, include_deleted):
    total = vol.record_count()
    names = {}              # rec -> (parent, name) for in-use records
    inuse_seq = {}          # in-use base records -> sequence number
    ext = defaultdict(list) # base -> extension segment dicts
    ext_names = defaultdict(list)
    for recno, raw in vol.iter_records():
        if recno % 200000 == 0:
            eprint(f"  scanning MFT {recno:,}/{total:,}")
        if raw[:4] != b"FILE":
            continue
        rec, torn = vol.fixup(raw)
        flags = struct.unpack_from("<H", rec, 0x16)[0]
        seq = struct.unpack_from("<H", rec, 0x10)[0]
        base_ref = struct.unpack_from("<Q", rec, 0x20)[0]
        base, bseq = base_ref & MASK48, base_ref >> 48
        in_use = flags & 1
        try:
            if base == 0:
                if in_use:
                    inuse_seq[recno] = seq
                    nm = best_name(file_names(rec))
                    if nm:
                        names[recno] = nm[:2]
                continue
            lsn = struct.unpack_from("<Q", rec, 0x08)[0]
            for fn in file_names(rec):
                ext_names[base].append(fn)
            for a in parse_attrs(rec):
                if a["type"] == ATTR_DATA and a["name_len"] == 0 and has_runs(a):
                    ext[base].append(seg_from(rec, a, recno, in_use, lsn, bseq, torn))
        except (ValueError, struct.error, IndexError):
            pass
    eprint(f"  scanned {total:,} records")

    targets = set(explicit)
    for base, segs in ext.items():
        if base in targets:
            continue
        freed = [s for s in segs if not s["in_use"]]
        if not freed:
            continue
        if base in inuse_seq:
            if not any(s["bseq"] == inuse_seq[base] for s in freed):
                continue
            brec = vol.read_record(base)
            if brec and any(a["type"] == ATTR_LIST for a in parse_attrs(brec)):
                continue  # still has an attribute list: not the CHKDSK pattern
            targets.add(base)
        elif include_deleted:
            targets.add(base)
    return targets, names, inuse_seq, ext, ext_names


def has_runs(a):
    """Non-resident attribute that actually maps something (an emptied/truncated
    attribute has highest VCN = -1, which reads as 2**64-1 unsigned)."""
    return a["nonres"] and a["last"] < (1 << 63) and a["last"] >= a["start"]


def seg_from(rec, a, recno, in_use, lsn, bseq, torn):
    return {"rec": recno, "in_use": in_use, "lsn": lsn, "bseq": bseq, "torn": torn,
            "start": a["start"], "last": a["last"], "flags": a["flags"], "cu": a["cu"],
            "runs": decode_runs(rec, a),
            "sizes": (a["alloc"], a["real"], a["init"]) if a["start"] == 0 else None}


def full_path(rec, names, extra=None, limit=64):
    parts, cur, seen = [], rec, set()
    first = names.get(rec) or extra
    if not first:
        return None
    parent, name = first
    parts.append(name)
    cur = parent
    while cur != ROOT and limit:
        if cur in seen or cur not in names:
            parts.append(f"<dir {cur:X}?>")
            break
        seen.add(cur)
        cur, nm = names[cur]
        parts.append(nm)
        limit -= 1
    return "/" + "/".join(reversed(parts))


def analyze(vol, base, inuse_seq, ext, names, ext_names, extra=(), notes=None):
    info = {"base": base, "base_hex": f"{base:X}", "in_use": base in inuse_seq}
    brec = vol.read_record(base)
    segs = []
    fn_extra = None
    if brec:
        bseq_now = struct.unpack_from("<H", brec, 0x10)[0]
        lsn = struct.unpack_from("<Q", brec, 0x08)[0]
        for a in parse_attrs(brec):
            if a["type"] == ATTR_DATA and a["name_len"] == 0 and has_runs(a):
                try:
                    segs.append(seg_from(brec, a, base, 1, lsn, bseq_now, False))
                except ValueError:
                    pass
        nm = best_name(file_names(brec))
        fn_extra = nm[:2] if nm else None
    if not fn_extra and ext_names.get(base):
        fn_extra = best_name(ext_names[base])[:2]
    want = inuse_seq.get(base)
    cand = ext.get(base, [])
    if want is None and cand:  # base freed: take the most common stamp
        counts = defaultdict(int)
        for s in cand:
            counts[s["bseq"]] += 1
        want = max(counts, key=counts.get)
    segs += [s for s in cand if s["bseq"] == want]
    segs += list(extra)
    info["path"] = full_path(base, names, fn_extra) or "(no name found)"
    info["name"] = (fn_extra or (None, f"record_{base:X}"))[1]

    segs.sort(key=lambda s: (s["start"], -s["lsn"]))
    chosen, conflicts = [], 0
    for s in segs:
        if chosen and s["start"] <= chosen[-1]["last"]:
            if (s["start"], s["last"], s["runs"]) != (chosen[-1]["start"], chosen[-1]["last"], chosen[-1]["runs"]):
                conflicts += 1
            continue
        chosen.append(s)
    if not chosen:
        info["status"] = "no data segments"
        return info, []
    last = max(s["last"] for s in chosen)
    gaps, expect = [], 0
    for s in chosen:
        if s["start"] > expect:
            gaps.append((expect, s["start"] - 1))
        expect = max(expect, s["last"] + 1)
    covered = sum(s["last"] - s["start"] + 1 for s in chosen)
    reasons = []
    for g0, g1 in gaps:
        why = sorted({n for s, n in (notes or {}).items() if g0 <= s <= g1})
        if not why:
            if g0 == 0 and info["in_use"]:
                why = ["start of the map was in the base record, which CHKDSK rewrote"]
            elif notes is not None:  # deep scan ran and found this file's list, but not this range
                why = ["no surviving extension record or attribute-list entry covers this range"]
            else:
                why = ["no surviving extension record maps this range (slot likely reused; --deep can confirm)"]
        reasons.append({"vcn": [g0, g1], "why": why})
    info["gap_reasons"] = reasons[:50]
    sizes = next((s["sizes"] for s in chosen if s["sizes"] and s["sizes"][1]), None)
    compressed = any(s["flags"] & 0x0001 for s in chosen) or any(s["cu"] for s in chosen)
    encrypted = any(s["flags"] & 0x4000 for s in chosen)
    cu = next((s["cu"] for s in chosen if s["cu"]), 4) if compressed else 0

    runs = [(v, l, c, s["in_use"]) for s in chosen for (v, l, c) in s["runs"]]
    alloc = sum(l for _, l, c, _ in runs if c is not None)
    freed_alloc = sum(l for _, l, c, iu in runs if c is not None and not iu)
    reused = sum(vol.count_in_use(c, l) for _, l, c, iu in runs if c is not None and not iu)
    zero = sampled = 0
    step = max(1, len(runs) // 200)
    for v, l, c, _ in runs[::step]:
        if c is None:
            continue
        for k in {0, l // 2, l - 1}:
            d = vol.read(( c + k) * vol.cluster, vol.cluster)
            sampled += 1
            zero += d.count(0) == len(d)
    info.update({
        "segments": len(chosen), "conflicts": conflicts, "last_vcn": last,
        "coverage_pct": round(100 * covered / (last + 1), 3), "gaps": gaps[:50], "gap_count": len(gaps),
        "size": sizes[1] if sizes else None, "size_known": bool(sizes),
        "compressed": compressed, "compression_unit_clusters": (1 << cu) if compressed else None,
        "encrypted": encrypted, "allocated_clusters": alloc,
        "freed_clusters": freed_alloc, "reused_clusters": reused,
        "reused_pct": round(100 * reused / freed_alloc, 3) if freed_alloc else 0.0,
        "zero_sample_pct": round(100 * zero / sampled, 1) if sampled else None,
    })
    if encrypted:
        info["status"] = "EFS-encrypted: cannot recover raw"
    elif gaps:
        info["status"] = "partial (gaps)"
    elif reused:
        info["status"] = "complete map, some clusters reused since CHKDSK"
    else:
        info["status"] = "recoverable"
    return info, [(v, l, c) for v, l, c, _ in runs]


# ------------------------------------------------------------ deep: why gaps

# An $ATTRIBUTE_LIST entry for an unnamed $DATA segment is 0x20 bytes:
#   type 0x80 | entry length 0x20 | name length 0 | name offset 0x1A |
#   lowest VCN (8) | MFT reference of the record holding that segment (8) | id (2)
# CHKDSK typically deletes a list because its *start* is corrupt ("does not
# contain standard information attribute"), so search for these individual
# entries rather than for the start of a list.
DATA_ENTRY = b"\x80\x00\x00\x00\x20\x00\x00\x1a"


def deep_find_list_entries(vol, bases):
    """Search the volume's free stretches for surviving attribute-list $DATA
    entries. Returns {base: [entry dicts]} (the base itself is learned from
    the record each entry points at, since entries don't name their owner)."""
    C = vol.cluster
    step = (64 << 20) // C
    lcn, total, done = 0, vol.total_clusters, 0
    hits = []  # (start_vcn, rec, seq, lcn_of_hit)
    while lcn < total:
        n = min(step, total - lcn)
        if vol.count_in_use(lcn, n) < n:
            buf = vol.read(lcn * C, n * C)
            p = buf.find(DATA_ENTRY)
            while p != -1:
                if p % 8 == 0 and p + 0x20 <= len(buf):
                    start, ref = struct.unpack_from("<QQ", buf, p + 8)
                    if start < (1 << 40) and (ref & MASK48) < vol.record_count():
                        hits.append((start, ref & MASK48, ref >> 48, lcn + p // C))
                p = buf.find(DATA_ENTRY, p + 1)
        lcn += n
        done += 1
        if done % 256 == 0:
            eprint(f"  deep scan {100 * lcn / total:5.1f}%")

    # A hit's owner: the record it points at, if that record is (or was) an
    # extension of one of our bases, or the base itself. Group hits by the
    # attribute list they sit in (same cluster neighbourhood) and attribute the
    # whole group to whichever base most of its resolvable entries name.
    want = set(bases)
    owner_cache = {}

    def owner(rec):
        if rec not in owner_cache:
            raw = vol._rec_at(vol.mft_runs, rec)
            o = None
            if raw and raw[:4] == b"FILE":
                b = struct.unpack_from("<Q", vol.fixup(raw)[0], 0x20)[0] & MASK48
                o = rec if (b == 0 and rec in want) else (b if b in want else None)
            elif rec in want:
                o = rec
            owner_cache[rec] = o
        return owner_cache[rec]

    groups = defaultdict(list)
    for h in hits:
        groups[h[3] // 16].append(h)  # entries of one list sit within a few clusters
    found = defaultdict(list)
    for g in groups.values():
        votes = defaultdict(int)
        for start, rec, seq, _ in g:
            o = owner(rec)
            if o is not None:
                votes[o] += 1
        if not votes:
            continue
        base = max(votes, key=votes.get)
        for start, rec, seq, _ in g:
            found[base].append({"type": ATTR_DATA, "named": False, "start": start, "rec": rec, "seq": seq})
    return found


def resolve_missing(vol, base, entries, names):
    """Check every $DATA slot the old attribute list names. Returns
    (segments still intact, {start_vcn: explanation})."""
    extra, notes = [], {}
    for e in entries:
        if e["type"] != ATTR_DATA or e["named"]:
            continue
        s, r = e["start"], e["rec"]
        if r == base:
            notes[s] = "segment was in the base record, which CHKDSK rewrote"
            continue
        raw = vol._rec_at(vol.mft_runs, r)
        if not raw or raw[:4] != b"FILE":
            notes[s] = f"MFT slot {r:X} no longer holds a valid record (overwritten)"
            continue
        rec, torn = vol.fixup(raw)
        flags, seq = struct.unpack_from("<H", rec, 0x16)[0], struct.unpack_from("<H", rec, 0x10)[0]
        bref = struct.unpack_from("<Q", rec, 0x20)[0]
        b, lsn = bref & MASK48, struct.unpack_from("<Q", rec, 0x08)[0]
        recycled = f" (sequence {e['seq']:X} -> {seq:X})" if seq != e["seq"] else ""
        if b == base:
            hit = None
            for a in parse_attrs(rec):
                if a["type"] == ATTR_DATA and a["name_len"] == 0 and has_runs(a) and a["start"] == s:
                    try:
                        hit = seg_from(rec, a, r, flags & 1, lsn, bref >> 48, torn)
                    except ValueError:
                        pass
            if hit:
                extra.append(hit)
                notes[s] = f"recovered from MFT slot {r:X} via the old attribute list"
            else:
                notes[s] = f"MFT slot {r:X} still tagged to this file but no longer holds this segment"
        elif b == 0 and flags & 1:
            notes[s] = f"MFT slot {r:X} reused{recycled} by {full_path(r, names) or 'another file'}"
        elif b:
            notes[s] = f"MFT slot {r:X} reused{recycled} as part of {full_path(b, names) or f'record {b:X}'}"
        else:
            notes[s] = f"MFT slot {r:X} reused{recycled}, then freed again"
    return extra, notes


def orphan_slot_report(vol, orphans, targets, names):
    """For CHKDSK-listed orphan slots: which now belong to other files."""
    reused = []
    for o in sorted(orphans):
        raw = vol._rec_at(vol.mft_runs, o)
        if not raw or raw[:4] != b"FILE":
            reused.append((o, "overwritten"))
            continue
        rec, _ = vol.fixup(raw)
        b = struct.unpack_from("<Q", rec, 0x20)[0] & MASK48
        in_use = struct.unpack_from("<H", rec, 0x16)[0] & 1
        if b in targets:
            continue
        owner = b if b else o
        reused.append((o, (full_path(owner, names) or f"record {owner:X}") + ("" if in_use else " (since freed)")))
    return reused


# --------------------------------------------------------------------- extract

def lznt1_chunk(d):
    out, i, n = bytearray(), 0, len(d)
    while i < n:
        flags = d[i]; i += 1
        for b in range(8):
            if i >= n:
                break
            if not (flags >> b) & 1:
                out.append(d[i]); i += 1
            else:
                if i + 1 >= n:
                    raise ValueError("truncated token")
                tok = d[i] | (d[i + 1] << 8); i += 2
                pos, lmask, oshift = len(out) - 1, 0xFFF, 12
                while pos >= 0x10:
                    lmask >>= 1; oshift -= 1; pos >>= 1
                length, offset = (tok & lmask) + 3, (tok >> oshift) + 1
                start = len(out) - offset
                if start < 0:
                    raise ValueError("bad back-reference")
                if length <= offset:
                    out += out[start:start + length]
                else:
                    for k in range(length):
                        out.append(out[start + k])
    return out


def lznt1(buf):
    out, i = bytearray(), 0
    while i + 2 <= len(buf):
        h = buf[i] | (buf[i + 1] << 8)
        if h == 0:
            break
        size = (h & 0xFFF) + 1
        data = buf[i + 2:i + 2 + size]; i += 2 + size
        out += lznt1_chunk(data) if h & 0x8000 else data
    return bytes(out)


def _work(job):
    u, kind, data, unit_bytes = job
    if kind == "c":
        try:
            data = lznt1(data)
        except Exception as e:
            return u, None, str(e)
    return u, data[:unit_bytes], None


def iter_units(vol, runs, unit, last_vcn):
    """Yield (unit_index, [lcn or None]*unit) walking runs in VCN order."""
    runs = sorted(runs)
    ri, nunits = 0, last_vcn // unit + 1
    for u in range(nunits):
        lo, hi = u * unit, (u + 1) * unit
        slots = [None] * unit
        while ri < len(runs) and runs[ri][0] + runs[ri][1] <= lo:
            ri += 1
        j = ri
        while j < len(runs) and runs[j][0] < hi:
            v, l, c = runs[j]
            if c is not None:
                for k in range(max(v, lo), min(v + l, hi)):
                    slots[k - lo] = c + (k - v)
            j += 1
        yield u, slots


def extract(vol, info, runs, outp, jobs, size_override=None):
    size = size_override or info["size"] or (info["last_vcn"] + 1) * vol.cluster
    C = vol.cluster
    errors = 0
    os.makedirs(os.path.dirname(outp) or ".", exist_ok=True)
    with open(outp, "wb") as fo:
        if not info["compressed"]:
            for v, l, c in sorted(runs):
                if c is None:
                    continue
                fo.seek(v * C)
                src, left = c * C, l * C
                while left:
                    n = min(left, 16 << 20)
                    fo.write(vol.read(src, n)); src += n; left -= n
        else:
            unit = info["compression_unit_clusters"]
            ub = unit * C

            def jobs_gen():
                for u, slots in iter_units(vol, runs, unit, info["last_vcn"]):
                    have = [c for c in slots if c is not None]
                    if not have:
                        continue
                    buf = bytearray()
                    i = 0
                    while i < len(have):  # coalesce contiguous clusters into one read
                        j = i
                        while j + 1 < len(have) and have[j + 1] == have[j] + 1:
                            j += 1
                        buf += vol.read(have[i] * C, (j - i + 1) * C)
                        i = j + 1
                    yield u, ("r" if len(have) == unit else "c"), bytes(buf), ub

            if jobs > 1:
                from multiprocessing import Pool
                with Pool(jobs) as pool:
                    results = pool.imap(_work, jobs_gen(), chunksize=32)
                    errors = _write_units(fo, results, ub)
            else:
                errors = _write_units(fo, map(_work, jobs_gen()), ub)
        fo.truncate(size)
    return size, errors


def _write_units(fo, results, ub):
    errors = 0
    for i, (u, data, err) in enumerate(results):
        if err:
            errors += 1
            eprint(f"    unit {u}: {err}")
            continue
        fo.seek(u * ub); fo.write(data)
        if i and i % 8192 == 0:
            eprint(f"    {i:,} units")
    return errors


def safe_name(s):
    return re.sub(r'[\x00-\x1f<>:"\\|?*]', "_", s).strip() or "_"


# ------------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", help="NTFS partition device, partition image, or whole-disk image")
    ap.add_argument("--offset", type=int, default=0, help="byte offset of the NTFS partition (whole-disk images)")
    ap.add_argument("--out", default="./chkdsk_rescue", help="output directory (put it on a DIFFERENT disk)")
    ap.add_argument("--log", help="CHKDSK log text (e.g. Event Viewer 1001/26226 export)")
    ap.add_argument("--records", nargs="*", default=[], help="base MFT record numbers in hex")
    ap.add_argument("--include-deleted", action="store_true", help="also report files whose base record is gone")
    ap.add_argument("--extract", nargs="?", const="all", help="extract all found, or comma-separated hex records")
    ap.add_argument("--keep-paths", action="store_true", help="recreate original folders under --out")
    ap.add_argument("--size", action="append", default=[], help="HEXREC:BYTES size override when unknown")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="decompression processes")
    ap.add_argument("--deep", action="store_true",
                    help="for files with gaps, search free space for their old attribute lists to explain "
                         "(and where possible recover) the missing pieces; reads the volume's free space")
    args = ap.parse_args()

    st = os.stat(args.source)
    if stat.S_ISBLK(st.st_mode):
        try:
            if open(f"/sys/dev/block/{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}/ro").read().strip() != "1":
                eprint(f"WARNING: {args.source} is writable. Consider: blockdev --setro {args.source}")
        except OSError:
            pass

    prog = os.path.basename(sys.argv[0])
    if volume_kind(args.source, args.offset) == "BitLocker":
        extra = ""
        if args.offset:
            extra = ("\n\nThis volume is inside a whole-disk device/image at offset "
                     f"{args.offset}. Attach it first, e.g.:\n"
                     f"  losetup --find --show --read-only --offset {args.offset} {args.source}\n"
                     "and use the /dev/loopN it prints in place of the device above.")
        sys.exit(BITLOCKER_HELP.format(src=args.source, dev=args.source if not args.offset else "/dev/loopN",
                                       prog=prog, extra=extra))
    try:
        vol = NTFS(args.source, args.offset)
    except ValueError as e:
        parts = find_ntfs_partitions(args.source) if args.offset == 0 else []
        if parts:
            eprint(f"{args.source} is a whole disk. Partitions found:")
            for n, off, kind in parts:
                eprint(f"  partition {n}: {kind:9}  --offset {off}"
                       + ("   (encrypted: rerun with this offset for unlock steps)" if kind == "BitLocker" else ""))
            sys.exit(2)
        sys.exit(f"error: {e}")

    os.makedirs(args.out, exist_ok=True)
    check_output_location(st, args.out)

    print(f"NTFS: cluster {vol.cluster} B, record {vol.rec_size} B, {vol.record_count():,} MFT records")
    explicit, orphans = {int(r, 16) for r in args.records}, set()
    if args.log:
        bases, orphans = parse_log(args.log)
        print(f"log: {len(bases)} damaged base records, {len(orphans)} orphan segments listed")
        explicit |= bases
        for o in orphans:
            r = vol.read_record(o)
            # Only a still-free orphan tells us its owner; a reused slot belongs to someone else now.
            if r and not struct.unpack_from("<H", r, 0x16)[0] & 1:
                b = struct.unpack_from("<Q", r, 0x20)[0] & MASK48
                if b:
                    explicit.add(b)
    targets, names, inuse_seq, ext, ext_names = scan(vol, explicit, args.include_deleted)

    report, runs_by = [], {}
    for t in sorted(targets):
        info, runs = analyze(vol, t, inuse_seq, ext, names, ext_names)
        if info.get("status") == "no data segments" and t not in explicit:
            continue
        report.append(info); runs_by[t] = runs

    gapped = [i["base"] for i in report if i.get("gap_count") or not i.get("segments")]
    if args.deep and gapped:
        print(f"\ndeep scan: searching free space for remnants of the old attribute lists of {len(gapped)} file(s)...")
        lists = deep_find_list_entries(vol, gapped)
        for k, i in enumerate(report):
            if i["base"] in lists:
                extra, notes = resolve_missing(vol, i["base"], lists[i["base"]], names)
                info, runs = analyze(vol, i["base"], inuse_seq, ext, names, ext_names, extra, notes)
                info["attr_list_found"] = True
                report[k], runs_by[i["base"]] = info, runs
            elif i["base"] in gapped:
                for g in i.get("gap_reasons", []):
                    g["why"] = [w.replace("(slot likely reused; --deep can confirm)",
                                          "(slot likely reused; no attribute-list remnant survives to confirm)")
                                for w in g["why"]]
        missing = [f"{b:X}" for b in gapped if b not in lists]
        if missing:
            print(f"  no attribute-list remnants found for: {', '.join(missing)} (their list clusters were overwritten, "
                  "or the list was small enough to live inside the base record)")

    print(f"\n{'REC':>7}  {'SIZE':>15}  {'COVER':>7}  {'REUSED':>7}  {'CMP':3}  STATUS / PATH")
    for i in report:
        sz = f"{i['size']:,}" if i.get("size") else "?"
        print(f"{i['base_hex']:>7}  {sz:>15}  {i.get('coverage_pct', 0):6.2f}%  {i.get('reused_pct', 0):6.2f}%  "
              f"{'yes' if i.get('compressed') else 'no ':3}  {i['status']}\n{'':>7}  {i['path']}")
        for g in i.get("gap_reasons", [])[:5]:
            a_, b_ = g["vcn"]
            print(f"{'':>9}gap VCN 0x{a_:X}-0x{b_:X} ({(b_ - a_ + 1) * vol.cluster / 2**20:,.1f} MiB): {'; '.join(g['why'][:3])}"
                  + (f" (+{len(g['why']) - 3} more)" if len(g["why"]) > 3 else ""))
        if len(i.get("gap_reasons", [])) > 5:
            print(f"{'':>9}... {len(i['gap_reasons']) - 5} more gaps in report.json")
    if not report:
        print("  nothing found")

    if orphans:
        reused = orphan_slot_report(vol, orphans, targets, names)
        print(f"\nCHKDSK log: {len(reused)} of {len(orphans)} listed orphan slots have been reused since"
              + (" (some lost pieces cannot come back)" if reused else ""))
        for o, who in reused[:10]:
            print(f"  slot {o:X}: {who}")
        if len(reused) > 10:
            print(f"  ... {len(reused) - 10} more")

    with open(os.path.join(args.out, "report.json"), "w") as fo:
        json.dump(report, fo, indent=1)
    for t, runs in runs_by.items():
        with open(os.path.join(args.out, f"{t:X}.runs.tsv"), "w") as fo:
            fo.write("vcn\tlength\tlcn\n")
            for v, l, c in runs:
                fo.write(f"{v}\t{l}\t{'' if c is None else c}\n")
    print(f"\nreport: {os.path.join(args.out, 'report.json')}")

    if not args.extract:
        if report:
            print("next: rerun with --extract (all) or --extract REC,REC")
        return
    sel = None if args.extract == "all" else {int(x, 16) for x in args.extract.split(",")}
    sizes = {int(k, 16): int(v) for k, v in (s.split(":") for s in args.size)}
    todo = [i for i in report if (sel is None or i["base"] in sel) and i.get("segments")]
    need = sum(i.get("size") or (i["last_vcn"] + 1) * vol.cluster for i in todo)
    free = os.statvfs(args.out).f_bavail * os.statvfs(args.out).f_frsize
    if need > free:
        sys.exit(f"error: need {need:,} bytes, only {free:,} free in {args.out}")
    for i in todo:
        if i["encrypted"]:
            print(f"skip {i['base_hex']}: EFS-encrypted")
            continue
        if args.keep_paths and i["path"].startswith("/"):
            rel = [safe_name(p) for p in i["path"].strip("/").split("/")]
            outp = os.path.join(args.out, "files", *rel)
        else:
            outp = os.path.join(args.out, "files", f"{i['base_hex']}_{safe_name(i['name'])}")
        print(f"extracting {i['base_hex']} -> {outp}")
        size, errs = extract(vol, i, runs_by[i["base"]], outp, args.jobs, sizes.get(i["base"]))
        with open(outp, "rb") as f:
            head = f.read(16)
        print(f"  {size:,} bytes, decompression errors: {errs}, first bytes: {head.hex(' ')}")
        if i.get("gap_count"):
            print(f"  WARNING: {i['gap_count']} gap(s) zero-filled")
        if i.get("reused_clusters"):
            print(f"  WARNING: {i['reused_clusters']:,} clusters reused since CHKDSK; those regions may hold other data")


if __name__ == "__main__":
    main()
