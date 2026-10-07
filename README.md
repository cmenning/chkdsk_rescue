# chkdsk_rescue

Recover NTFS files that CHKDSK "repaired" into empty or truncated files.

`chkdsk_rescue.py` is a single, self-contained Python script. It reads an NTFS volume (or an image of one), finds files whose block maps CHKDSK threw away, rebuilds those maps from leftover metadata, and copies the files out intact. It never writes to the volume it is reading.

---

## The problem it solves

Large, heavily fragmented NTFS files can't fit their entire block map (the list of where each piece of the file lives on disk) into a single MFT record. NTFS spreads the map across several extra *extension records* and keeps an index of them in the file's `$ATTRIBUTE_LIST`.

If that attribute list gets corrupted (by a crash, a power loss, a buggy third-party NTFS driver, and so on), CHKDSK's "fix" goes like this:

1. It deletes the corrupt attribute list.
2. The extension records no longer belong to anything, so it deletes them too, logging lines like `Deleting orphan file record segment 1A2B`.
3. It frees the clusters those records pointed to and truncates the file, often to **0 bytes**.

The file still shows up in its folder, but it's empty or broken, and any application that uses it fails.

**The data usually isn't gone.** CHKDSK only marks things as free. Until something new is written over them:

- the freed extension records still hold their pieces of the block map, each tagged with the number of the file it belongs to, and
- the freed clusters still hold the file's contents.

This tool finds those records, reassembles the map, checks whether anything has been written over the file's clusters since, and extracts the file. It handles plain, sparse, and NTFS-compressed (LZNT1) files.

### Typical symptoms

- After a boot-time disk check, some large files (virtual machine disks, game asset packs, video, archives, databases) are suddenly 0 bytes or fail to open.
- The CHKDSK log contains lines like:
  ```
  The attribute list in file 0x1A2B does not contain standard information attribute.
  Deleted corrupt attribute list for file 1A2B.
  Deleting orphan file record segment 1A2C.
  ```
- A virtual machine fails with an error that one of its disk files can't be read.

### What it can't do

- **Overwritten data.** If new files have been written into the freed space, those regions are gone. The tool tells you how much, if any, of each file's space has been reused.
- **EFS-encrypted files.** They're detected and reported, but the raw encrypted data is useless without the keys.
- **Small files.** Files small enough to live entirely inside their own MFT record never use an attribute list, so this kind of damage doesn't happen to them.
- **Other kinds of damage.** Files that were simply deleted, overwritten, or corrupted for other reasons are outside its scope.

---

## Requirements

- **A Linux environment.** A live USB (SystemRescue, an Ubuntu live session, and so on) is ideal. Any Linux install works. WSL 2 on Windows works for disks Windows can release (see below).
- **Python 3.10 or newer.** Standard library only; nothing to install.
- **Read access to the source.** Usually means running as root for a device.
- **A separate destination disk** with enough free space for the recovered files (plus an image of the source, if you make one). The tool refuses to write onto the volume it's recovering from.
- **For BitLocker volumes:** `cryptsetup` 2.3 or newer (included in current live distros) and the volume's password or 48-digit recovery key. See [BitLocker-encrypted volumes](#bitlocker-encrypted-volumes).

**WSL 2 note:** `wsl --mount` can attach a physical disk to WSL, but only if Windows can take the whole disk offline, which it can't do for the disk Windows is running from. If the damaged volume shares a physical disk with `C:`, boot a live Linux USB instead.

---

## Before you run it

The freed space is only recoverable until something writes over it, so the first steps are all about stopping writes.

### 1. Stop using the volume

- Don't save, install, download, or move anything onto it.
- **Don't run CHKDSK again**, and don't let Windows schedule another check.
- Don't "fix" the empty files by deleting them or reinstalling over them yet.

If the volume is your Windows system disk, the less time Windows spends running, the better.

### 2. If it's an SSD: stop TRIM

When Windows tells an SSD that clusters are free (TRIM), the drive erases them, and that data can't be recovered by any tool. Windows runs a scheduled "retrim" of free space roughly weekly or monthly. From an elevated PowerShell:

```powershell
# When did it last retrim? (Look for your volume's drive letter or label.)
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-Defrag'} -MaxEvents 50 |
  Select-Object TimeCreated, Message | Format-List

# Turn off the scheduled optimize/retrim, and TRIM on delete
Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag'
fsutil behavior set DisableDeleteNotify 1
```

If the last retrim on that volume happened **before** the CHKDSK run, your data is still there. Re-enable both once you're done (see [After recovery](#after-recovery)).

### 3. Save the CHKDSK log

Optional, but it helps the tool and it's useful for your own records. The log is stored in the Windows event log (on the system drive, not the damaged volume):

```powershell
# Boot-time check (autochk)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1001} |
  Where-Object { $_.Message -match 'Checking file system' } |
  Select-Object -First 1 -ExpandProperty Message | Out-File chkdsk_log.txt

# Online check (chkdsk run from a running Windows)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=26226} |
  Select-Object -First 1 -ExpandProperty Message | Out-File chkdsk_log_online.txt
```

The event log often truncates long CHKDSK output. That's fine; the tool doesn't need a complete log.

### 4. Shut down completely

Use `shutdown /s /t 0` rather than the Start menu. With Fast Startup enabled, a normal shutdown leaves volumes in a half-hibernated state that Windows may write to when it next starts.

### 5. Boot Linux and protect the source

Boot your live USB and list the disks and partitions:

```bash
lsblk -o NAME,SIZE,FSTYPE,LABEL,MODEL,SERIAL
```

The output looks something like this:

```
NAME     SIZE FSTYPE LABEL     MODEL              SERIAL
sda    931.5G                  ExampleSSD 1TB     S1234567890
├─sda1   100M vfat
├─sda2 230.0G ntfs   Windows
└─sda3 701.3G ntfs   Data
sdb      3.6T                  ExampleHDD 4TB     WX0987654321
└─sdb1   3.6T ext4   backup
```

Lines without the `├─` / `└─` prefix are **whole disks** (`sda`, `sdb`), and the indented lines under them are that disk's **partitions** (`sda1`, `sda2`, ...). Find the damaged volume by its size, filesystem (`ntfs`, or blank for a BitLocker volume), and label, which is usually the drive name Windows shows. In this example, if the damaged volume is the one called "Data", the partition is `sda3` and the disk it lives on is `sda`. Use the model and serial number to be sure you have the right physical disk.

Names depend on the drive type: SATA and USB drives appear as `sda`, `sdb`, and so on, with partitions `sda1`, `sda2`; NVMe drives appear as `nvme0n1`, with partitions `nvme0n1p1`, `nvme0n1p2`. Names can change between boots, so check again each time.

Then make both the disk and the partition read-only at the block level, so nothing in the session can write to them. Below, `sdX` stands for the disk name and `sdX2` for the damaged partition (in the example, `sda` and `sda3`):

```bash
blockdev --setro /dev/sdX          # the whole disk, e.g. /dev/sda
blockdev --setro /dev/sdX2         # the damaged partition, e.g. /dev/sda3
blockdev --getro /dev/sdX2         # prints 1 if it worked
```

The rest of this guide uses the same placeholders: `/dev/sdX` for the disk and `/dev/sdX2` (or `/dev/<volume>`) for the damaged partition.

Don't mount the damaged volume read-write, even briefly.

### 6. Check the drive's health

```bash
smartctl -a /dev/sdX
```

Watch for nonzero reallocated, pending, or uncorrectable sector counts. A failing drive changes the plan (see the next step).

### 7. Image it (recommended)

Working from an image means every pass after this one carries zero risk to the original. Mount a destination disk with plenty of space, then:

```bash
ddrescue -n /dev/<volume> /mnt/dest/volume.img /mnt/dest/volume.map
```

Replace `<volume>` with the damaged partition's device name from the `lsblk` output in step 5. Match it by size, filesystem (`ntfs`, or blank for BitLocker), and label, which is usually the name Windows shows for the drive. For example, if the damaged volume appears as a partition named `nvme0n1p3` or `sdb2`, use `/dev/nvme0n1p3` or `/dev/sdb2`. Image the partition, not the whole disk (`nvme0n1`, `sdb`), unless you want every partition on it.

`/mnt/dest` is wherever you mounted the destination disk. The `.map` file lets ddrescue resume if interrupted; keep it next to the image.

**Imaging is strongly recommended when:**
- the drive shows any SMART problems or read errors (ddrescue handles bad sectors gracefully; this tool doesn't),
- you expect to run the tool several times, or
- you can't guarantee nothing will write to the original.

**Going straight to the device is reasonable when** the drive is healthy, it's set read-only, and you just want a quick scan. A scan only reads the MFT and the allocation bitmap, so it's fast.

**Prefer a Linux filesystem (such as ext4) for the destination disk.** Writing large files to NTFS from Linux through NTFS-3G is a known source of the very corruption this tool exists to clean up.

### BitLocker-encrypted volumes

On a BitLocker volume everything past the boot sector is encrypted, including the MFT, so the tool can't read it directly. If you point it at one, it detects BitLocker and prints these steps instead of scanning.

Unlock the volume **read-only** in Linux, then run the tool on the unlocked view:

```bash
cryptsetup bitlkDump /dev/sdX2                               # confirm BitLocker, list protectors
cryptsetup open --type bitlk --readonly /dev/sdX2 unlocked   # asks for password or recovery key
python3 chkdsk_rescue.py /dev/mapper/unlocked --out /mnt/dest/rescue
cryptsetup close unlocked
```

- **Image first, unlock second.** Image the *encrypted* partition with ddrescue as usual, then unlock the image: `cryptsetup open --type bitlk --readonly /mnt/dest/volume.img unlocked`. The image stays encrypted at rest.
- **Recovery key.** If the drive normally unlocks automatically through the TPM, Linux can't use that; you need the 48-digit recovery key. For personal devices it's usually saved in the owner's Microsoft account; on managed devices, IT holds it. Windows "Device encryption" is BitLocker too.
- **Freed space still decrypts.** BitLocker encrypts sectors, not files, so data CHKDSK only marked as free is still there and decrypts normally.
- **If `cryptsetup` rejects the volume**, `dislocker` is an alternative that presents the decrypted volume as a file you can point the tool at.
- **Whole-disk images:** attach the BitLocker partition as a loop device first (`losetup --find --show --read-only --offset BYTES disk.img`), then unlock the `/dev/loopN` it prints. The tool prints the right offset if you point it at the whole disk.

---

## Usage

```
python3 chkdsk_rescue.py SOURCE [options]
```

`SOURCE` can be:

- an NTFS **partition** device (`/dev/sdX2`) or **partition image** (`volume.img`), or
- a **whole-disk** device or image. The tool lists the NTFS and BitLocker partitions it finds and the `--offset` to use for each, or
- an **unlocked BitLocker volume** (`/dev/mapper/<name>`).

Run it once without `--extract` to see what it finds, then again with `--extract` to recover.

### Options

| Option | What it does |
|---|---|
| `--out DIR` | Where the report and recovered files go. Default `./chkdsk_rescue`. Must not be on the volume being recovered; the tool follows encryption and device-mapper layers down to the physical disk to check, and warns if it's merely another partition of the same disk. |
| `--offset BYTES` | Byte offset of the NTFS partition inside a whole-disk device or image. The tool prints the right value if you point it at a whole disk. |
| `--log FILE` | A saved CHKDSK log (UTF-8 or UTF-16, so PowerShell output works as-is). Every file the log names is included, every orphan segment it lists is traced back to its file, and the tool reports which of those segments have since been reused by other files. Optional: without it, the tool auto-detects damaged files. |
| `--records HEX ...` | Specific MFT record numbers (hex, as CHKDSK prints them) to analyze, whether or not auto-detection flags them. |
| `--include-deleted` | Also report files whose own base record has been freed, not just truncated. Off by default because it also turns up ordinary deleted files. |
| `--deep` | For files with gaps in their reconstructed map: searches the volume's free space for surviving entries from each file's old attribute list (even a list CHKDSK judged corrupt usually has intact entries). Each entry says which MFT slot held a piece of the map, so missing pieces get a specific explanation, and any piece still intact is recovered automatically. Reads all free space on the volume, so it can take a while. |
| `--extract` | Extract every file found. |
| `--extract REC,REC` | Extract only the listed records (hex, comma-separated). |
| `--keep-paths` | Recreate each file's original folder structure under `OUT/files/`. Without it, files are saved flat as `OUT/files/<record>_<name>`. |
| `--size HEXREC:BYTES` | Set a file's size by hand when the tool can't determine it (shown as `?` in the report). Repeatable. |
| `--jobs N` | Number of processes for decompressing NTFS-compressed files. Default: all CPU cores. |

### How auto-detection decides what's damaged

A file is flagged when **all** of these are true:

- it still exists (its base MFT record is in use),
- one or more *freed* extension records are tagged as belonging to it, with a matching sequence number, and
- it no longer has an attribute list.

That combination is the fingerprint of this specific CHKDSK repair. Healthy fragmented files still have their attribute lists, so they're not flagged.

---

## Reading the report

Example output (illustrative):

```
    REC             SIZE    COVER   REUSED  CMP  STATUS / PATH
   1A2B    4,294,967,296  100.00%    0.00%  no   recoverable
         /Projects/archive/backup-2024.zip
   3C4D      812,646,400   91.40%    0.00%  yes  partial (gaps)
         /Media/Video/raw/clip_0042.mov
         gap VCN 0x1F400-0x20BFF (24.0 MiB): MFT slot 2E91 reused by /Users/someone/AppData/Local/Temp/tmp8F3A.tmp
```

| Column | Meaning |
|---|---|
| `REC` | The file's base MFT record number, in hex. Matches the numbers in CHKDSK logs. Use these with `--records` and `--extract`. |
| `SIZE` | The file's original size, recovered from its metadata. `?` means unknown; supply it with `--size` if you know it. |
| `COVER` | How much of the file's block map was reconstructed. 100% means every piece is accounted for. |
| `REUSED` | How much of the file's freed space is now allocated to other files. Those regions probably hold someone else's data now. |
| `CMP` | Whether the file is NTFS-compressed. Handled automatically. |

### Statuses

| Status | Meaning |
|---|---|
| `recoverable` | Complete map, nothing overwritten. Expect a perfect recovery. |
| `complete map, some clusters reused since CHKDSK` | Every piece is located, but some of the file's space has been reused. Those regions will contain the wrong data. |
| `partial (gaps)` | Some pieces of the map couldn't be found. Gaps are written as zeros. Each gap is listed with the likely reason; `--deep` can give a definite one. |
| `EFS-encrypted` | Can't be recovered in usable form. |
| `no data segments` | Nothing usable was found for a record you asked about. |

### Gap explanations

| Explanation | What it means |
|---|---|
| start of the map was in the base record, which CHKDSK rewrote | The first piece of the map lived in the file's own record, and CHKDSK replaced it when truncating the file. That piece is gone. |
| MFT slot X reused by /path/to/file | A new file now occupies the record that held this piece. |
| MFT slot X no longer holds a valid record | The record was overwritten. |
| recovered from MFT slot X via the old attribute list | Only appears with `--deep`: the piece was found after all and is included. |
| no surviving extension record maps this range (slot likely reused; --deep can confirm) | The default explanation without `--deep`; usually a reused record. |
| ...no attribute-list remnant survives to confirm | `--deep` ran, but nothing of this file's old attribute list survived, so the specific slot can't be identified. |
| no surviving extension record or attribute-list entry covers this range | `--deep` found part of the file's old list, but not the entries for this range. |

### Files written to `--out`

| File | Contents |
|---|---|
| `report.json` | Everything in the table plus details: every gap with its reason, cluster counts, compression unit size, and so on. |
| `<REC>.runs.tsv` | The reconstructed block map for each file (VCN, length, LCN). Useful for manual work or other tools. |
| `files/` | Recovered files, after `--extract`. |

---

## Examples

All paths are placeholders; substitute your own devices and mount points.

**Scan a partition image (auto-detect damaged files):**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --out /mnt/dest/rescue
```

**Scan the partition directly (healthy drive, set read-only first):**
```bash
blockdev --setro /dev/sdX && blockdev --setro /dev/sdX2
python3 chkdsk_rescue.py /dev/sdX2 --out /mnt/dest/rescue
```

**Whole-disk image: find the partition offset, then scan:**
```bash
python3 chkdsk_rescue.py /mnt/dest/disk.img
#   /mnt/dest/disk.img is a whole disk. NTFS partitions found:
#     partition 2: --offset 1048576
python3 chkdsk_rescue.py /mnt/dest/disk.img --offset 1048576 --out /mnt/dest/rescue
```

**Use a saved CHKDSK log:**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --log chkdsk_log.txt --out /mnt/dest/rescue
```

**Look at specific files CHKDSK mentioned:**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --records 1A2B 3C4D --out /mnt/dest/rescue
```

**Explain (and try to close) gaps:**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --deep --out /mnt/dest/rescue
```

**Extract everything, keeping the original folder structure:**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --out /mnt/dest/rescue --extract --keep-paths
```

**Extract two specific files:**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --out /mnt/dest/rescue --extract 1A2B,3C4D
```

**BitLocker volume (image of the encrypted partition):**
```bash
cryptsetup open --type bitlk --readonly /mnt/dest/volume.img unlocked
python3 chkdsk_rescue.py /dev/mapper/unlocked --out /mnt/dest/rescue --extract
cryptsetup close unlocked
```

**Supply a size the tool couldn't determine:**
```bash
python3 chkdsk_rescue.py /mnt/dest/volume.img --out /mnt/dest/rescue --extract 3C4D --size 3C4D:812646400
```

---

## After recovery

### Verify before you trust it

A complete map with no reuse should produce a perfect file, but check anyway, in whatever way fits the file type:

- **Anything with a known checksum or a backup copy:** compare (`sha256sum`, `cmp`).
- **Archives:** test them (`7z t`, `unzip -t`).
- **Media:** play or decode them (`ffmpeg -v error -i file -f null -`).
- **Virtual machine disks:** check the container (`qemu-img check`) and the guest filesystem inside it (attach read-only with `qemu-nbd --read-only`, then `fsck -n`).
- **Game or application files:** usually faster to let the launcher's "verify files" or "repair" feature replace them than to recover them at all.

### Put files back

- Recover everything you need **before** making any changes to the damaged volume.
- When copying files back to an NTFS volume, prefer doing it from Windows (its own NTFS driver) over writing from Linux with NTFS-3G.
- If the files lived in an NTFS-compressed folder and were very large, consider turning compression off for that folder (`compact /u`). Compressing huge files is what fragments them badly enough to need an attribute list in the first place.

### Clean up

Once everything is safe:

1. Run `chkdsk X: /f` on the volume to finish the repair properly.
2. Delete the broken originals and copy the recovered versions into place.
3. Re-enable TRIM and scheduled optimization if you turned them off:
   ```powershell
   fsutil behavior set DisableDeleteNotify 0
   Enable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag'
   ```
4. Keep the image until you're sure you won't need it again.

---

## Troubleshooting

| Message | Fix |
|---|---|
| `... is a whole disk. Partitions found` | Rerun with the `--offset` shown, or point the tool at the partition device instead. For a BitLocker partition, rerunning with its offset prints unlock steps. |
| `... is BitLocker-encrypted` | Unlock it read-only with `cryptsetup` and point the tool at `/dev/mapper/<name>`. See [BitLocker-encrypted volumes](#bitlocker-encrypted-volumes). |
| `no NTFS boot sector` | Wrong device or offset, or the boot sector itself is damaged. Check with `lsblk` and `blkid`. |
| `Read-only file system` | `--out` points somewhere you can't write, such as a read-only mount. Choose a writable location on another disk. |
| `--out is on the volume being recovered` | By design, including when the source is reached through an encryption or mapper layer. Write to a different physical disk. |
| `WARNING: --out is on another partition of the same physical disk` | Safe for the source data, but it adds load to the same drive, which matters if the drive is failing. A separate disk is better. |
| `note: could not determine which disk --out lives on` | Happens with FUSE-mounted destinations (such as NTFS-3G). The tool can't verify the location, so double-check it yourself. |
| `WARNING: /dev/sdX2 is writable` | Not fatal, but run `blockdev --setro` on the disk and partition before continuing. |
| `decompression errors: N` | Some compressed blocks didn't decode cleanly, usually because a gap or reused clusters fell inside them. Those 64 KiB blocks will be wrong in the output. |
| `SyntaxError` or `AttributeError: 'int' object has no attribute 'bit_count'` | Python is older than 3.10. Use a newer live USB or install a newer Python. |

---

## Safety summary

- The tool opens the source **read-only** and never writes to it.
- It refuses to write output onto the volume it's reading from, tracing through encryption and device-mapper layers (such as an unlocked BitLocker volume) to the underlying disk, and warns if the source device isn't set read-only.
- It recognizes BitLocker volumes and explains how to unlock them read-only, rather than misreading encrypted data.
- It checks free space at the destination before extracting.
- Recovered files that came from partial maps or reused space are flagged during extraction; gaps are filled with zeros, never with guesses.

---

## License

BSD 3-Clause. See [LICENSE](LICENSE).
