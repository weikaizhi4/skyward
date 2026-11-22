use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use skyward_config::ramdisk as paths;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

mod avb;
mod described;

use skyward_bootimg::{BootImage, Ramdisk, VendorBootImage};

/// A stock image Skyward can be built on: a boot/recovery image with
/// `ANDROID!`, or a vendor_boot image with `VNDRBOOT` whose vendor ramdisk
/// is the recovery ramdisk on some Unisoc phones.
enum StockImage {
    Boot(BootImage),
    Vendor(VendorBootImage),
}

impl StockImage {
    fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if bytes.starts_with(b"VNDRBOOT") {
            Ok(StockImage::Vendor(VendorBootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))?))
        } else {
            Ok(StockImage::Boot(BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))?))
        }
    }

    fn ramdisk(&self) -> &[u8] {
        match self {
            StockImage::Boot(image) => &image.ramdisk,
            StockImage::Vendor(image) => &image.ramdisk,
        }
    }

    fn set_ramdisk(&mut self, ramdisk: Vec<u8>) {
        match self {
            StockImage::Boot(image) => image.ramdisk = ramdisk,
            StockImage::Vendor(image) => image.ramdisk = ramdisk,
        }
    }

    fn set_dtb(&mut self, dtb: Vec<u8>) {
        match self {
            StockImage::Boot(image) => image.dtb = dtb,
            StockImage::Vendor(image) => image.dtb = dtb,
        }
    }

    fn set_kernel(&mut self, kernel: Vec<u8>) -> Result<()> {
        match self {
            StockImage::Boot(image) => {
                image.kernel = kernel;
                Ok(())
            }
            StockImage::Vendor(_) => anyhow::bail!("a vendor_boot image has no kernel to replace"),
        }
    }

    fn append_cmdline(&mut self, text: &str) -> Result<()> {
        match self {
            StockImage::Boot(image) => image.append_cmdline(text),
            StockImage::Vendor(image) => image.append_cmdline(text),
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            StockImage::Boot(image) => image.to_bytes(),
            StockImage::Vendor(image) => image.to_bytes(),
        }
    }

    fn partition_name(&self) -> &'static str {
        match self {
            StockImage::Boot(_) => "recovery",
            StockImage::Vendor(_) => "vendor_boot",
        }
    }

    fn header_version(&self) -> u32 {
        match self {
            StockImage::Boot(image) => image.header_version(),
            StockImage::Vendor(image) => image.header_version(),
        }
    }

    fn kernel_len(&self) -> usize {
        match self {
            StockImage::Boot(image) => image.kernel.len(),
            StockImage::Vendor(_) => 0,
        }
    }

    fn ramdisk_len(&self) -> usize {
        self.ramdisk().len()
    }
}

/// Builds Skyward recovery images from a device's own stock images.
#[derive(Parser)]
#[command(name = "skyward-pack")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print an image's header and the files in its ramdisk.
    List { image: PathBuf },
    /// Write one ramdisk file to stdout.
    Cat { image: PathBuf, path: String },
    /// Unpack and pack an image's ramdisk unchanged, to check that a rebuilt
    /// archive keeps every entry.
    Repack { image: PathBuf, out: PathBuf },
    /// Join a kernel and another image's ramdisk into one boot image.
    Boot {
        /// Image holding the kernel (the device's boot partition).
        #[arg(long)]
        kernel: PathBuf,
        /// Image holding the ramdisk.
        #[arg(long)]
        ramdisk: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a Skyward recovery image on top of the device's stock recovery:
    /// its init, adbd, SELinux policy and libraries stay, the recovery
    /// service becomes Skyward. The image fills the whole partition and ends
    /// in an unsigned AVB footer of its own.
    Recovery {
        /// The device's stock recovery image: the whole partition, as the
        /// phone or a full update package holds it, ending in its AVB footer.
        #[arg(long)]
        stock: PathBuf,
        /// Skyward built for the device (aarch64-linux-android).
        #[arg(long)]
        binary: PathBuf,
        /// The first program of a system installed beside the installed
        /// one, skyward-system-init built for the device and linked
        /// statically.
        #[arg(long)]
        system_init: PathBuf,
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// The UI typeface.
        #[arg(long)]
        font: PathBuf,
        /// The terminal's monospaced typeface.
        #[arg(long)]
        mono: PathBuf,
        /// The monospaced typeface's licence, which goes with it.
        #[arg(long)]
        mono_license: PathBuf,
        /// Append `androidboot.selinux=permissive` to the cmdline.
        #[arg(long)]
        permissive: bool,
        /// Replace the DTB section.
        #[arg(long)]
        dtb: Option<PathBuf>,
        /// Replace the kernel with a raw ARM64 Image.
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Start adbd in the recovery domain before the service.
        #[arg(long)]
        debug_adbd: bool,
        /// Start adbd early in its stock domain.
        #[arg(long)]
        early_adbd: bool,
        /// Point adbd's shell context at `u:r:adbd:s0`.
        #[arg(long)]
        patch_adbd_shell: bool,
        /// Keep the stock cmdline, prop.default and adbd binary; add only
        /// rules guarded by ro.bootmode=recovery. For a vendor_boot ramdisk
        /// that the normal system also uses.
        #[arg(long)]
        recovery_only: bool,
        /// Debug only: append unconditional early-init/init/boot rules that
        /// force adbd up, even if the recovery service never starts.
        #[arg(long)]
        force_adbd: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the stock build a device's recovery is made on, as lines of
    /// name=value: its version, where its full update package is, and the
    /// SHA-256 of the recovery partition in that package. Given somewhere
    /// to write it, also take that partition out of the package on its
    /// server, reading only what the partition takes, and write it there
    /// once its SHA-256 is that one.
    Stock {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// Where to write the stock recovery image.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Take what a device's own partitions say of the programs they carry
    /// out of its stock build's full update package on its server: the
    /// init scripts, the service descriptions, the accounts and the build
    /// properties of each partition that carries such programs, written
    /// under `out` as the partition and then the path in it. Only the
    /// parts of the package that hold these files are downloaded, each
    /// checked against the package's own sum of it.
    Described {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// A partition to take them out of; vendor, odm and system_ext
        /// when none is named.
        #[arg(long = "partition")]
        partitions: Vec<String>,
        /// The folder to write the files under, which is not there yet.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::List { image } => list(&image),
        Cmd::Cat { image, path } => {
            let img = StockImage::read(&image)?;
            let rd = Ramdisk::decode(img.ramdisk())?;
            let e = rd.find(&path).with_context(|| format!("{path} is not in the ramdisk"))?;
            std::io::stdout().write_all(&e.data)?;
            Ok(())
        }
        Cmd::Repack { image, out } => {
            let mut img = StockImage::read(&image)?;
            let stock = img.ramdisk().to_vec();
            img.set_ramdisk(Ramdisk::decode(&stock)?.encode_like(&stock)?);
            write(&out, &img, &img.to_bytes()?)
        }
        Cmd::Boot { kernel, ramdisk, out } => {
            let mut img = BootImage::read(&ramdisk)?;
            img.kernel = BootImage::read(&kernel)?.kernel;
            write_boot(&out, &img, &img.to_bytes()?)
        }
        Cmd::Recovery { stock, binary, system_init, config, font, mono, mono_license, permissive, dtb, kernel, debug_adbd, early_adbd, patch_adbd_shell, recovery_only, force_adbd, out } => {
            let size = partition_size(&stock)?;
            let mut img = StockImage::read(&stock)?;
            if !recovery_only {
                if let Some(kernel) = kernel {
                    img.set_kernel(std::fs::read(&kernel).with_context(|| format!("read {}", kernel.display()))?)?;
                }
                if let Some(dtb) = dtb {
                    img.set_dtb(std::fs::read(&dtb).with_context(|| format!("read {}", dtb.display()))?);
                }
                if permissive {
                    img.append_cmdline("androidboot.selinux=permissive")?;
                }
            }
            let mut rd = Ramdisk::decode(img.ramdisk())?;
            if force_adbd {
                let init_rc = "system/etc/init/hw/init.rc";
                let entry = rd.find(init_rc).with_context(|| format!("{init_rc} is not in the ramdisk"))?;
                let mut text = String::from_utf8(entry.data.clone()).context("init.rc is not UTF-8")?;
                text.push_str("\n# Skyward debug: force adbd up even if recovery never starts.\non early-init\n    setprop sys.usb.config_disable 0\n    setprop sys.usb.config adb\non init\n    start adbd\non boot\n    start adbd\n");
                rd.replace(init_rc, text.into_bytes())?;
            }
            // A stock recovery ramdisk has no third-party tree; refuse to build
            // on top of another custom recovery.
            if let Some(e) = rd.entries.iter().find(|e| e.name == "FFiles" || e.name.starts_with("twres")) {
                anyhow::bail!("{} holds {}, which is not a stock recovery", stock.display(), e.name);
            }
            let read = |p: &PathBuf| std::fs::read(p).with_context(|| format!("read {}", p.display()));
            skyward_config::DeviceConfig::load(&config)?;
            rd.replace(paths::RECOVERY, read(&binary)?)?;
            // Install scripts look for the commands a stock recovery lacks
            // among its programs, and its unzip there too, a link to ziptool
            // until it points here; the recovery binary is each of them.
            let (_, recovery) = paths::RECOVERY.rsplit_once('/').expect("the recovery binary is in a folder");
            for command in paths::COMMANDS {
                rd.link(command, recovery)?;
            }
            rd.add(paths::SYSTEM_INIT, 0o755, read(&system_init)?)?;
            rd.add(paths::CONFIG, 0o644, read(&config)?)?;
            rd.add(paths::FONT, 0o644, read(&font)?)?;
            rd.add(paths::MONO, 0o644, read(&mono)?)?;
            rd.add(paths::MONO_LICENSE, 0o644, read(&mono_license)?)?;
            // A stock ramdisk may run logd without any scheduling profiles,
            // and logd stops as soon as it cannot find the one it asks for.
            if rd.find(paths::TASK_PROFILES).is_none() {
                rd.add(paths::TASK_PROFILES, 0o644, TASK_PROFILES.to_vec())?;
            }
            if recovery_only {
                // The vendor_boot ramdisk is used by the normal system too.
                // Keep the cmdline, prop.default and adbd binary stock; every
                // added rule is guarded by ro.bootmode=recovery.
                rd.add(paths::MTP_RC, 0o644, MTP_RC_RECOVERY.to_vec())?;
                rd.add("system/etc/init/skyward-recovery.rc", 0o644, RECOVERY_ONLY_RC.to_vec())?;
                rd.add(
                    "system/bin/skyward-permissive",
                    0o755,
                    b"#!/system/bin/sh\nsetenforce 0 2>/dev/null\necho 0 > /sys/fs/selinux/enforce 2>/dev/null\ntouch /dev/skyward-permissive\n".to_vec(),
                )?;
                // The user confirmed the vendor_boot prop.default is not
                // read by the normal system on this phone. Keep the stock
                // cmdline and adbd, but let recovery's adbd keep root.
                let stock_props = &rd
                    .find(paths::PROP_DEFAULT)
                    .with_context(|| format!("{} is not in the ramdisk", paths::PROP_DEFAULT))?
                    .data;
                // Keep the stock build/version lines in place: the normal
                // system may read this vendor_boot prop.default too, and a
                // missing ro.vendor.build.security_patch can stop its
                // keymaster/vold early. Only append the recovery adbd
                // settings; the later line wins in init's property map.
                let mut props = stock_props.to_vec();
                props.extend_from_slice(b"\nro.secure=0\nro.adb.secure=0\nro.debuggable=1\nservice.adb.root=1\nro.ota.allow_downgrade=true\n");
                rd.replace(paths::PROP_DEFAULT, props)?;
                if early_adbd {
                    rd.add("system/etc/init/skyward-adbd.rc", 0o644, ADBD_RECOVERY_RC.to_vec())?;
                }
                // Put the permissive switch before class_start recovery in
                // the recovery's own init, so Skyward itself starts after it.
                let common = "init.recovery.common.rc";
                if let Some(entry) = rd.find(common) {
                    let text = String::from_utf8(entry.data.clone()).context("init.recovery.common.rc is not UTF-8")?;
                    let old = "on property:ro.bootmode=recovery\n    class_start recovery";
                    let new = "on property:ro.bootmode=recovery\n    exec - root root -- /system/bin/skyward-permissive\n    wait /dev/skyward-permissive 5\n    class_start recovery";
                    if text.contains(old) {
                        rd.replace(common, text.replace(old, new).into_bytes())?;
                    } else {
                        eprintln!("warning: {common} has no ro.bootmode=recovery class_start recovery block");
                    }
                }
            } else {
                rd.add(paths::MTP_RC, 0o644, MTP_RC.to_vec())?;
                // On an unlocked device adbd keeps root when ro.secure is 0 and
                // lets any computer in without authorization when ro.adb.secure is
                // 0; init lets a later line of a property file override an earlier
                // one. update_engine refuses a package built before the recovery
                // itself unless both of the last two are set; the recovery checks
                // packages against the installed system instead.
                let stock_props = &rd
                    .find(paths::PROP_DEFAULT)
                    .with_context(|| format!("{} is not in the ramdisk", paths::PROP_DEFAULT))?
                    .data;
                let mut props = without(stock_props, &BUILD_VERSION);
                props.extend_from_slice(b"\nro.secure=0\nro.adb.secure=0\nro.debuggable=1\nro.ota.allow_downgrade=true\n");
                if debug_adbd || early_adbd {
                    props.extend_from_slice(b"service.adb.root=1\n");
                    // Start adbd from the phone's own recovery init, so adb is
                    // there even when the recovery service fails.
                    let early: Vec<String> = rd
                        .entries
                        .iter()
                        .map(|e| e.name.clone())
                        .filter(|n| n.starts_with("init.recovery.") && n.ends_with(".rc") && !n.contains("common") && !n.contains("usb") && !n.contains("service") && !n.contains("logd") && !n.contains("ldconfig") && !n.contains("mksh") && !n.contains("vold_decrypt") && !n.contains("hlthchrg"))
                        .collect();
                    let rc = b"\n# Skyward debug: adb before the recovery service.\non init\n    setprop sys.usb.config adb\non boot\n    start adbd\n";
                    if early.is_empty() {
                        // Some Unisoc vendor_boot ramdisks carry only
                        // init.recovery.common.rc; a file under /system/etc/init
                        // is parsed by init just the same.
                        rd.add("system/etc/init/skyward-adbd.rc", 0o644, rc.to_vec())?;
                    } else {
                        for name in early {
                            let mut data = rd.find(&name).expect("the entry was just found").data.clone();
                            data.extend_from_slice(rc);
                            rd.replace(&name, data)?;
                        }
                    }
                }
                if patch_adbd_shell {
                    let adbd = rd.find("system/bin/adbd").with_context(|| "system/bin/adbd is not in the ramdisk")?;
                    let mut data = adbd.data.clone();
                    let old = b"u:r:shell:s0";
                    let new = b"u:r:adbd:s0\0";
                    ensure!(data.windows(old.len()).filter(|w| *w == old).count() == 1, "adbd holds no single u:r:shell:s0");
                    let at = data.windows(old.len()).position(|w| w == old).expect("the string was just counted");
                    data[at..at + old.len()].copy_from_slice(new);
                    rd.replace("system/bin/adbd", data)?;
                }
                if debug_adbd {
                    // A user build's recovery policy has neither su nor a
                    // usable shell subprocess domain; adbd aborts when it tries
                    // to switch the shell to it. Run adbd itself in the
                    // recovery domain, which exists, so the switch is skipped.
                    // (This domain may not start adbd at all on some policies;
                    // prefer early_adbd when only `adb pull` is needed.)
                    let init_rc = "system/etc/init/hw/init.rc";
                    let rc = rd.find(init_rc).with_context(|| format!("{init_rc} is not in the ramdisk"))?;
                    let text = String::from_utf8(rc.data.clone()).context("init.rc is not UTF-8")?;
                    let text = text
                        .replace("--root_seclabel=u:r:su:s0", "--root_seclabel=u:r:recovery:s0")
                        .replace("seclabel u:r:adbd:s0", "seclabel u:r:recovery:s0");
                    rd.replace(init_rc, text.into_bytes())?;
                }
                rd.replace(paths::PROP_DEFAULT, props)?;
            }
            let stock = img.ramdisk().to_vec();
            img.set_ramdisk(rd.encode_like(&stock)?);
            let bytes = img.to_bytes()?;
            let partition = img.partition_name();
            write(&out, &img, &avb::footed(&bytes, partition, size, &Sha256::digest(&bytes))?)
        }
        Cmd::Stock { config, out } => {
            let stock = skyward_config::DeviceConfig::load(&config)?.stock.with_context(|| format!("{} names no stock build", config.display()))?;
            println!("version={}\npackage={}\nrecovery={}", stock.version, stock.package, stock.recovery);
            match out {
                Some(out) => take_stock_recovery(&stock, &out),
                None => Ok(()),
            }
        }
        Cmd::Described { config, partitions, out } => {
            let stock = skyward_config::DeviceConfig::load(&config)?.stock.with_context(|| format!("{} names no stock build", config.display()))?;
            let partitions = if partitions.is_empty() { skyward_programs::phone::PARTITIONS.map(str::to_string).to_vec() } else { partitions };
            described::take(&stock.package, &partitions, &out)
        }
    }
}

/// The partition a recovery is made on, as a full update package names it.
const RECOVERY: &str = "recovery";

/// Take the recovery partition out of the stock build's full update package
/// on its server, reading only what that partition takes of it, and write it
/// to `out` once its SHA-256 is the one the configuration names.
fn take_stock_recovery(stock: &skyward_config::Stock, out: &Path) -> Result<()> {
    let parent = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("make {}", parent.display()))?;
    // Taken out beside where it goes, so it is moved there whole.
    let work = tempfile::Builder::new().prefix(".stock").tempdir_in(parent).with_context(|| format!("make a folder in {}", parent.display()))?;
    let payload = unpayload::Payload::open_url(&stock.package).with_context(|| format!("open {}", stock.package))?;
    let options = unpayload::ExtractOptions { output_dir: work.path().to_path_buf(), partitions: vec![RECOVERY.into()], ..Default::default() };
    let report = |event: unpayload::Event<'_>| match event {
        unpayload::Event::Started { partitions } => {
            for (name, bytes) in partitions {
                println!("taking {name} out of the package: {bytes} bytes");
            }
        }
        unpayload::Event::Extracted(image) => println!("took {} out: {} bytes", image.partition, image.size),
        unpayload::Event::Progress { .. } => {}
    };
    let taken = payload.extract(&options, &report).with_context(|| format!("take {RECOVERY} out of {}", stock.package))?;
    let image = taken.iter().find(|i| i.partition == RECOVERY).with_context(|| format!("{} holds no {RECOVERY} partition", stock.package))?;
    let sum = hex::encode(image.sha256.as_deref().context("the package's own sum of the image was not checked")?);
    ensure!(sum == stock.recovery, "the {RECOVERY} partition in {} has the SHA-256 {sum}, where the configuration names {}", stock.package, stock.recovery);
    std::fs::rename(&image.path, out).with_context(|| format!("move {} to {}", image.path.display(), out.display()))?;
    println!("wrote {} ({} bytes), its SHA-256 the one the configuration names", out.display(), image.size);
    Ok(())
}

/// The size of the partition `stock` fills: all of it, as the phone and a
/// full update package hold it, which its AVB footer ends.
fn partition_size(stock: &Path) -> Result<usize> {
    let mut file = File::open(stock).with_context(|| format!("open {}", stock.display()))?;
    let size = file.metadata().with_context(|| format!("stat {}", stock.display()))?.len();
    let mut magic = [0u8; 4];
    if size >= 64 {
        file.seek(SeekFrom::Start(size - 64)).with_context(|| format!("seek in {}", stock.display()))?;
        file.read_exact(&mut magic).with_context(|| format!("read {}", stock.display()))?;
    }
    ensure!(
        &magic == b"AVBf",
        "{} does not end in an AVB footer; give the whole partition, as the phone or a full update package holds it",
        stock.display()
    );
    Ok(usize::try_from(size)?)
}

/// What a recovery image says about the build it is: the version and patch
/// levels of its own ramdisk's system and vendor partition, which are older
/// than those installed beside it whenever the phone has taken an update.
/// The phone's secure services read these to tell the secure world which
/// build is running, and keys the installed system made are refused when
/// they say the wrong one, so they are left out here for the recovery to
/// fill in from the installed system once it has that mounted.
const BUILD_VERSION: [&str; 3] = ["ro.build.version.release", "ro.build.version.security_patch", "ro.vendor.build.security_patch"];

/// The scheduling profiles a recovery's programs look up by name. A
/// recovery's cgroup setup mounts no controllers, so of all a system's
/// profiles do, only the timer slack applies here.
const TASK_PROFILES: &[u8] = include_bytes!("task_profiles.json");

/// The init rules that give the USB port file transfer beside adb, which a
/// stock recovery does not offer.
const MTP_RC: &[u8] = include_bytes!("mtp.rc");

/// File transfer rules that run only when the phone booted into recovery.
const MTP_RC_RECOVERY: &[u8] = include_bytes!("mtp-recovery.rc");

/// Early adbd, only when the phone booted into recovery.
const ADBD_RECOVERY_RC: &[u8] = include_bytes!("adbd-recovery.rc");

/// The recovery-only permissive switch.
const RECOVERY_ONLY_RC: &[u8] = include_bytes!("recovery-only.rc");

/// A property file without the lines that set any of `names`.
fn without(props: &[u8], names: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(props.len());
    for line in props.split_inclusive(|b| *b == b'\n') {
        let key = line.split(|b| *b == b'=').next().unwrap_or_default();
        if !names.iter().any(|n| n.as_bytes() == key) {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Write `bytes`, the boot image `img` makes, to `out`.
fn write_boot(out: &Path, img: &BootImage, bytes: &[u8]) -> Result<()> {
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!(
        "wrote {} ({} bytes kernel, {} bytes ramdisk, {} bytes in all)",
        out.display(),
        img.kernel.len(),
        img.ramdisk.len(),
        bytes.len()
    );
    Ok(())
}

/// Write `bytes`, the stock image `img` makes, to `out`.
fn write(out: &Path, img: &StockImage, bytes: &[u8]) -> Result<()> {
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!(
        "wrote {} ({} bytes kernel, {} bytes ramdisk, {} bytes in all)",
        out.display(),
        img.kernel_len(),
        img.ramdisk_len(),
        bytes.len()
    );
    Ok(())
}

fn list(image: &Path) -> Result<()> {
    let img = StockImage::read(image)?;
    println!(
        "header v{}  kernel {} bytes  ramdisk {} bytes",
        img.header_version(),
        img.kernel_len(),
        img.ramdisk_len()
    );
    if img.ramdisk().is_empty() {
        return Ok(());
    }
    let rd = Ramdisk::decode(img.ramdisk())?;
    for e in &rd.entries {
        println!("{:06o} {:>5}:{:<5} {:>10}  {}", e.mode, e.uid, e.gid, e.data.len(), e.name);
    }
    println!("{} entries", rd.entries.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_that_set_a_name_are_the_only_ones_left_out() {
        let props = b"ro.build.id=TQ\nro.build.version.release=13\nro.build.version.release_or_codename=13\nro.product.name=ishtar\n\
ro.vendor.build.security_patch=2026-10-01\nro.vendor.build.security_patch_level=1\n";
        let out = without(props, &BUILD_VERSION);
        let text = String::from_utf8(out).expect("property files are text");
        assert!(!text.contains("ro.build.version.release=13"));
        assert!(!text.contains("ro.vendor.build.security_patch=2026-10-01"), "the vendor partition's patch level is left out too");
        assert!(text.contains("ro.build.version.release_or_codename=13"), "a longer name is left alone");
        assert!(text.contains("ro.vendor.build.security_patch_level=1"), "a longer name is left alone");
        assert!(text.contains("ro.build.id=TQ") && text.contains("ro.product.name=ishtar"));
    }

    #[test]
    fn the_profiles_name_all_the_recovery_asks_for() {
        let profiles: serde_json::Value = serde_json::from_slice(TASK_PROFILES).expect("the profiles are JSON");
        let names = |key: &str| -> Vec<String> {
            profiles[key].as_array().expect("a list").iter().map(|p| p["Name"].as_str().expect("a name").to_string()).collect()
        };
        let (plain, aggregate) = (names("Profiles"), names("AggregateProfiles"));
        // What libprocessgroup asks for when a program sets its scheduling
        // policy, and what the recovery's own init scripts give logd.
        let asked = [
            "SCHED_SP_DEFAULT",
            "SCHED_SP_BACKGROUND",
            "SCHED_SP_FOREGROUND",
            "SCHED_SP_TOP_APP",
            "SCHED_SP_SYSTEM",
            "SCHED_SP_RT_APP",
            "CPUSET_SP_DEFAULT",
            "CPUSET_SP_BACKGROUND",
            "CPUSET_SP_FOREGROUND",
            "CPUSET_SP_TOP_APP",
            "CPUSET_SP_SYSTEM",
            "CPUSET_SP_RESTRICTED",
            "BlkIOBackground",
            "BlkIOForeground",
            "ServiceCapacityLow",
        ];
        for name in asked {
            assert!(plain.iter().chain(&aggregate).any(|n| n == name), "{name} is missing");
        }
        for a in profiles["AggregateProfiles"].as_array().expect("a list") {
            for part in a["Profiles"].as_array().expect("a list") {
                let part = part.as_str().expect("a name");
                assert!(plain.iter().any(|n| n == part), "{} is made of {part}, which is not a profile", a["Name"]);
            }
        }
    }

    #[test]
    fn the_partition_is_as_large_as_a_stock_image_ending_in_its_footer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.img");
        let mut whole = vec![0u8; 8192];
        whole[8192 - 64..8192 - 60].copy_from_slice(b"AVBf");
        std::fs::write(&path, &whole).unwrap();
        assert_eq!(partition_size(&path).unwrap(), 8192);
        std::fs::write(&path, &whole[..8000]).unwrap();
        assert!(partition_size(&path).is_err(), "an image cut short of its partition's end");
        std::fs::write(&path, b"AVBf").unwrap();
        assert!(partition_size(&path).is_err(), "too short to end in a footer");
    }

    #[test]
    fn a_file_without_a_last_newline_keeps_its_last_line() {
        let out = without(b"a=1\nro.build.version.release=13", &BUILD_VERSION);
        assert_eq!(out, b"a=1\n");
        let kept = without(b"a=1\nb=2", &BUILD_VERSION);
        assert_eq!(kept, b"a=1\nb=2");
    }
}
