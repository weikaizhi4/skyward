use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0Versioned, HeaderV3, OsVersionPatch};
use anyhow::{anyhow, ensure, Context, Result};
use sha1::{Digest, Sha1};
use std::fs;
use std::path::Path;

const PAGE: usize = 4096;

/// Boot image v0-v4: header plus the sections it names. v0-v2 use the
/// header page size; v3/v4 use 4096-byte pages.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    /// Second-stage bootloader (v0-v2).
    pub second: Vec<u8>,
    /// Recovery DTBO (v1/v2).
    pub recovery_dtbo: Vec<u8>,
    /// DTB (v2).
    pub dtb: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = Header::parse(&mut Cursor::new(bytes)).context("header")?;
        let (kernel, ramdisk, second, recovery_dtbo, dtb) = match &header {
            Header::V3(h) => {
                let kernel = section(bytes, HeaderV3::kernel_position(), h.kernel_size, "kernel")?;
                let ramdisk = section(bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?;
                (kernel, ramdisk, Vec::new(), Vec::new(), Vec::new())
            }
            Header::V0(h) => {
                let kernel = section(bytes, h.kernel_position(), h.kernel_size, "kernel")?;
                let ramdisk = section(bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?;
                let second = section(bytes, h.second_bootloader_position(), h.second_bootloader_size, "second stage bootloader")?;
                let (recovery_dtbo, dtb) = match h.versioned {
                    HeaderV0Versioned::V0 => (Vec::new(), Vec::new()),
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => {
                        (section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?, Vec::new())
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => {
                        let recovery_dtbo = section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?;
                        let dtb = section(bytes, h.dtb_position().expect("a version 2 header names the DTB's position"), dtb_size, "DTB")?;
                        (recovery_dtbo, dtb)
                    }
                };
                (kernel, ramdisk, second, recovery_dtbo, dtb)
            }
        };
        Ok(BootImage { header, kernel, ramdisk, second, recovery_dtbo, dtb })
    }

    /// Header version, 0 through 4.
    pub fn header_version(&self) -> u32 {
        self.header.header_version()
    }

    /// OS version and patch level.
    pub fn os_version(&self) -> OsVersionPatch {
        match &self.header {
            Header::V0(h) => h.osversionpatch,
            Header::V3(h) => h.osversionpatch,
        }
    }

    /// SHA-1 id for v0-v2: each section followed by its length.
    fn v0_digest(&self) -> [u8; 32] {
        let mut hasher = Sha1::new();
        for part in [&self.kernel, &self.ramdisk, &self.second, &self.recovery_dtbo, &self.dtb] {
            hasher.update(part);
            hasher.update((part.len() as u32).to_le_bytes());
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out[..digest.len()].copy_from_slice(&digest);
        out
    }

    /// Append `text` to the kernel command line.
    pub fn append_cmdline(&mut self, text: &str) -> Result<()> {
        let cmdline: &mut [u8; 1536] = match &mut self.header {
            Header::V0(h) => &mut h.cmdline,
            Header::V3(h) => &mut h.cmdline,
        };
        let used = cmdline.iter().position(|&b| b == 0).unwrap_or(cmdline.len());
        let space = usize::from(used != 0);
        let end = used + space + text.len();
        ensure!(end < cmdline.len(), "the command line has no room for {text:?}");
        if space == 1 {
            cmdline[used] = b' ';
        }
        cmdline[used + space..end].copy_from_slice(text.as_bytes());
        Ok(())
    }

    /// The image with sizes taken from its parts. A version 4 header keeps its
    /// version but carries no boot signature; unlocked bootloaders do not ask
    /// for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        match &mut header {
            Header::V3(h) => {
                h.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                h.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                h.v4_signature_size = h.v4_signature_size.map(|_| 0);
            }
            Header::V0(h) => {
                h.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                h.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                h.second_bootloader_size = u32::try_from(self.second.len()).context("second stage bootloader size")?;
                // v0-v2 store this offset in recovery_dtbo_addr; move it
                // with the ramdisk.
                let recovery_dtbo_offset = h.recovery_dtbo_position() as u64;
                match &mut h.versioned {
                    HeaderV0Versioned::V0 => {}
                    HeaderV0Versioned::V1 { recovery_dtbo_size, recovery_dtbo_addr, .. } => {
                        *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery DTBO size")?;
                        *recovery_dtbo_addr = recovery_dtbo_offset;
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, recovery_dtbo_addr, dtb_size, .. } => {
                        *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery DTBO size")?;
                        *recovery_dtbo_addr = recovery_dtbo_offset;
                        *dtb_size = u32::try_from(self.dtb.len()).context("DTB size")?;
                    }
                }
                h.hash_digest = self.v0_digest();
            }
        }

        let mut out = Vec::new();
        header.write(&mut out).context("write header")?;
        match &header {
            Header::V3(_) => {
                pad(&mut out, PAGE);
                out.extend_from_slice(&self.kernel);
                pad(&mut out, PAGE);
                out.extend_from_slice(&self.ramdisk);
                pad(&mut out, PAGE);
            }
            Header::V0(h) => {
                let page = h.page_size.max(1) as usize;
                pad(&mut out, page);
                out.extend_from_slice(&self.kernel);
                pad(&mut out, page);
                out.extend_from_slice(&self.ramdisk);
                pad(&mut out, page);
                out.extend_from_slice(&self.second);
                pad(&mut out, page);
                if !matches!(h.versioned, HeaderV0Versioned::V0) {
                    out.extend_from_slice(&self.recovery_dtbo);
                    pad(&mut out, page);
                }
                if matches!(h.versioned, HeaderV0Versioned::V2 { .. }) {
                    out.extend_from_slice(&self.dtb);
                    pad(&mut out, page);
                }
            }
        }
        Ok(out)
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    let left = out.len() % page;
    if left != 0 {
        out.resize(out.len() + page - left, 0);
    }
}
