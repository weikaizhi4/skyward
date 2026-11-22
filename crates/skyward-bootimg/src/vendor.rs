//! Android vendor_boot images, header version 3 and 4: the vendor ramdisk
//! (which on some phones is the recovery ramdisk), the DTB and, in version
//! 4, the vendor ramdisk table and bootconfig.

use abootimg_oxide::binrw::io::Cursor;
use abootimg_oxide::binrw::{BinRead, BinWrite};
use abootimg_oxide::VendorHeader;
use anyhow::{anyhow, ensure, Context, Result};
use std::fs;
use std::path::Path;

/// A vendor_boot image split into its header and the sections the header
/// names. The ramdisk is kept as the image holds it, compressed.
pub struct VendorBootImage {
    pub header: VendorHeader,
    pub ramdisk: Vec<u8>,
    pub dtb: Vec<u8>,
    /// The version 4 vendor ramdisk table, kept as it is except for the
    /// first entry's size when the ramdisk grows.
    pub table: Vec<u8>,
    pub bootconfig: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

fn pad(out: &mut Vec<u8>, page: usize) {
    let left = out.len() % page;
    if left != 0 {
        out.resize(out.len() + page - left, 0);
    }
}

impl VendorBootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        VendorBootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = VendorHeader::read(&mut Cursor::new(bytes)).context("vendor_boot header")?;
        let ramdisk = section(bytes, header.ramdisk_position(), header.vendor_ramdisk_size, "vendor ramdisk")?;
        let dtb = section(bytes, header.dtb_position(), header.dtb_size, "DTB")?;
        let (table, bootconfig) = match &header.v4 {
            Some(v4) => {
                let table = section(bytes, header.ramdisk_table_position(), v4.vendor_ramdisk_table_size, "vendor ramdisk table")?;
                let bootconfig = section(
                    bytes,
                    header.bootconfig_position().expect("a version 4 header names the bootconfig's position"),
                    v4.bootconfig_size,
                    "bootconfig",
                )?;
                (table, bootconfig)
            }
            None => (Vec::new(), Vec::new()),
        };
        Ok(VendorBootImage { header, ramdisk, dtb, table, bootconfig })
    }

    pub fn header_version(&self) -> u32 {
        self.header.header_version()
    }

    /// Add `text` to the command line the bootloader passes the kernel.
    pub fn append_cmdline(&mut self, text: &str) -> Result<()> {
        let cmdline = &mut self.header.cmdline;
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

    /// The image with sizes taken from its parts. The table's first entry
    /// describes the one ramdisk this image carries; its size follows the
    /// ramdisk, its offset stays zero.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        header.vendor_ramdisk_size = u32::try_from(self.ramdisk.len()).context("vendor ramdisk size")?;
        header.dtb_size = u32::try_from(self.dtb.len()).context("DTB size")?;
        let mut table = self.table.clone();
        if let Some(v4) = &mut header.v4 {
            ensure!(v4.vendor_ramdisk_table_entry_num >= 1, "the vendor ramdisk table has no entry");
            ensure!(table.len() >= 8, "the vendor ramdisk table is shorter than its first entry");
            table[0..4].copy_from_slice(&(self.ramdisk.len() as u32).to_le_bytes());
            table[4..8].copy_from_slice(&0u32.to_le_bytes());
            v4.vendor_ramdisk_table_size = u32::try_from(table.len()).context("vendor ramdisk table size")?;
            v4.bootconfig_size = u32::try_from(self.bootconfig.len()).context("bootconfig size")?;
        }
        let page = header.page_size.max(1) as usize;
        let mut header_bytes = Cursor::new(Vec::new());
        header.write(&mut header_bytes).context("write vendor_boot header")?;
        let mut out = header_bytes.into_inner();
        pad(&mut out, page);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, page);
        out.extend_from_slice(&self.dtb);
        pad(&mut out, page);
        out.extend_from_slice(&table);
        pad(&mut out, page);
        out.extend_from_slice(&self.bootconfig);
        pad(&mut out, page);
        Ok(out)
    }
}
