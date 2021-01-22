
use std::error::Error;
use std::fmt;
use std::iter;
use std::mem;

use std::collections::{HashMap, BTreeSet};
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;

// use anyhow::Result;

pub type FastMap64<K, V> = HashMap<K, V, BuildHasherDefault<FnvHasher>>;

pub type Gva = u64;
pub type Gpa = u64;

pub const fn page_off(a: Gpa) -> (Gpa, usize) {
    (a & !0xfff, a as usize & 0xfff)
}

const fn pml4_index(gva: Gva) -> u64 {
    gva >> (12 + (9 * 3)) & 0x1ff
}

const fn pdpt_index(gva: Gva) -> u64 {
    gva >> (12 + (9 * 2)) & 0x1ff
}

const fn pd_index(gva: Gva) -> u64 {
    (gva >> 21) & 0x1ff
}

const fn pt_index(gva: Gva) -> u64 {
    (gva >> 12) & 0x1ff
}

const fn base_flags(gpa: Gpa) -> (Gpa, u64) {
    (gpa & !0xfff & 0x000f_ffff_ffff_ffff, gpa & 0x1ff)
}

const fn pte_flags(pte: Gva) -> (Gpa, u64) {
    (pte & !0xfff & 0x000f_ffff_ffff_ffff, pte & 0xfff)
}

const fn page_offset(gva: Gva) -> u64 {
    gva & 0xfff
}

pub trait X64VirtualAddressSpace {
    fn read_gpa(&self, gpa: Gpa, buf: &mut [u8]) -> Result<(), VirtMemError>;

    fn write_gpa(&mut self, gpa: Gpa, data: &[u8]) -> Result<(), VirtMemError>;

    fn read_gpa_u64(&self, gpa: Gpa) -> Result<u64, VirtMemError> {
        let mut buf = [0; mem::size_of::<u64>()];
        self.read_gpa(gpa, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_gva_u64(&self, cr3: Gpa, gva: Gva) -> Result<u64, VirtMemError> {
        let mut buf = [0; mem::size_of::<u64>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_gva_u32(&self, cr3: Gpa, gva: Gva) -> Result<u32, VirtMemError> {
        let mut buf = [0; mem::size_of::<u32>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_gva_u16(&self, cr3: Gpa, gva: Gva) -> Result<u16, VirtMemError> {
        let mut buf = [0; mem::size_of::<u16>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_gva_u8(&self, cr3: Gpa, gva: Gva) -> Result<u8, VirtMemError> {
        let mut buf = [0; mem::size_of::<u8>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u8::from_le_bytes(buf))
    }

    fn read_gva(&self, cr3: Gpa, gva: Gva, buf: &mut [u8]) -> Result<(), VirtMemError> {
        let mut off = 0;

        for (start, sz) in chunked(gva, buf.len()) {
            let gpa = self.translate_gva(cr3, start)?;
            self.read_gpa(gpa, &mut buf[off..off + sz])?;
            off += sz;
        }

        Ok(())
    }

    fn write_gva(&mut self, cr3: Gpa, gva: Gva, buf: &[u8]) -> Result<(), VirtMemError> {
        let mut off = 0;

        for (start, sz) in chunked(gva, buf.len()) {
            let gpa = self.translate_gva(cr3, start)?;
            self.write_gpa(gpa, &buf[off..off + sz])?;
            off += sz;
        }

        Ok(())
    }

    fn translate_gva(&self, cr3: Gpa, gva: Gva) -> Result<Gpa, VirtMemError> {
        let (pml4_base, _) = base_flags(cr3);

        let pml4e_addr = pml4_base + pml4_index(gva) * 8;
        let pml4e = self.read_gpa_u64(pml4e_addr)?;

        let (pdpt_base, pml4e_flags) = base_flags(pml4e);

        if pml4e_flags & 1 == 0 {
            return Err(VirtMemError::Pml4eNotPresent);
        }

        let pdpte_addr = pdpt_base + pdpt_index(gva) * 8;
        let pdpte = self.read_gpa_u64(pdpte_addr)?;

        let (pd_base, pdpte_flags) = base_flags(pdpte);

        if pdpte_flags & 1 == 0 {
            return Err(VirtMemError::PdpteNotPresent);
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1
        if pdpte_flags & (1 << 7) != 0 {
            // let res = (pdpte & 0xffff_ffff_c000_0000) + (gva & 0x3fff_ffff);
            let res = pd_base + (gva & 0x3fff_ffff);
            return Ok(res);
        }

        let pde_addr = pd_base + pd_index(gva) * 8;
        let pde = self.read_gpa_u64(pde_addr)?;

        let (pt_base, pde_flags) = base_flags(pde);

        if pde_flags & 1 == 0 {
            return Err(VirtMemError::PdeNotPresent);
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18
        if pde_flags & (1 << 7) != 0 {
            // let res = (pde & 0xffff_ffff_ffe0_0000) + (gva & 0x1f_ffff);
            let res = pt_base + (gva & 0x1f_ffff);
            return Ok(res);
        }

        let pte_addr = pt_base + pt_index(gva) * 8;
        let pte = self.read_gpa_u64(pte_addr)?;

        let (pte_paddr, pte_flags) = pte_flags(pte);

        if pte_flags & 1 == 0 {
            return Err(VirtMemError::PteNotPresent);
        }

        Ok(pte_paddr + page_offset(gva))
    }

    fn _translate_gva_range(&self, cr3: Gpa, gva: Gva) -> Result<(Gpa, usize), VirtMemError> {
        let (pml4_base, _) = base_flags(cr3);

        let pml4e_addr = pml4_base + pml4_index(gva) * 8;
        let pml4e = self.read_gpa_u64(pml4e_addr)?;

        let (pdpt_base, pml4e_flags) = base_flags(pml4e);

        if pml4e_flags & 1 == 0 {
            return Err(VirtMemError::Pml4eNotPresent);
        }

        let pdpte_addr = pdpt_base + pdpt_index(gva) * 8;
        let pdpte = self.read_gpa_u64(pdpte_addr)?;

        let (pd_base, pdpte_flags) = base_flags(pdpte);

        if pdpte_flags & 1 == 0 {
            return Err(VirtMemError::PdpteNotPresent);
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1
        if pdpte_flags & (1 << 7) != 0 {
            // let res = (pdpte & 0xffff_ffff_c000_0000) + (gva & 0x3fff_ffff);
            // let res = pd_base + (gva & 0x3fff_ffff);
            return Ok((pd_base, 0x40000000));
        }

        let pde_addr = pd_base + pd_index(gva) * 8;
        let pde = self.read_gpa_u64(pde_addr)?;

        let (pt_base, pde_flags) = base_flags(pde);

        if pde_flags & 1 == 0 {
            return Err(VirtMemError::PdeNotPresent);
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18
        if pde_flags & (1 << 7) != 0 {
            // let res = (pde & 0xffff_ffff_ffe0_0000) + (gva & 0x1f_ffff);
            // let res = pt_base + (gva & 0x1f_ffff);
            return Ok((pt_base, 0x200000));
        }

        let pte_addr = pt_base + pt_index(gva) * 8;
        let pte = self.read_gpa_u64(pte_addr)?;

        let (pte_paddr, pte_flags) = pte_flags(pte);

        if pte_flags & 1 == 0 {
            return Err(VirtMemError::PteNotPresent);
        }

        Ok((pte_paddr, 0x1000))
    }

    fn translate_gva_with_pages(&self, cr3: Gpa, gva: Gva) -> Result<TranslatedAddress, VirtMemError> {
        let (pml4_base, _) = base_flags(cr3);

        let pml4e_addr = pml4_base + pml4_index(gva) * 8;
        let pml4e = self.read_gpa_u64(pml4e_addr)?;

        let (pdpt_base, pml4e_flags) = base_flags(pml4e);

        if pml4e_flags & 1 == 0 {
            return Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: None,
                pd: None,
                pt: None,
                gpa: None,
                size: None,
            })
        }

        let pdpte_addr = pdpt_base + pdpt_index(gva) * 8;
        let pdpte = self.read_gpa_u64(pdpte_addr)?;

        let (pd_base, pdpte_flags) = base_flags(pdpte);

        if pdpte_flags & 1 == 0 {
            return Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: Some(pdpt_base),
                pd: None,
                pt: None,
                gpa: None,
                size: None,
            })
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1
        if pdpte_flags & (1 << 7) != 0 {
            // let res = (pdpte & 0xffff_ffff_c000_0000) + (gva & 0x3fff_ffff);
            let gpa = pd_base + (gva & 0x3fff_ffff);
            return Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: Some(pdpt_base),
                pd: None,
                pt: None,
                gpa: Some(gpa),
                size: Some(GpaSize::Size1G),
            })
        }

        let pde_addr = pd_base + pd_index(gva) * 8;
        let pde = self.read_gpa_u64(pde_addr)?;

        let (pt_base, pde_flags) = base_flags(pde);

        if pde_flags & 1 == 0 {
            return Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: Some(pdpt_base),
                pd: Some(pd_base),
                pt: None,
                gpa: None,
                size: None,
            })
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18
        if pde_flags & (1 << 7) != 0 {
            // let res = (pde & 0xffff_ffff_ffe0_0000) + (gva & 0x1f_ffff);
            let gpa = pt_base + (gva & 0x1f_ffff);
            return Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: Some(pdpt_base),
                pd: Some(pd_base),
                pt: None,
                gpa: Some(gpa),
                size: Some(GpaSize::Size2M),
            })
        }

        let pte_addr = pt_base + pt_index(gva) * 8;
        let pte = self.read_gpa_u64(pte_addr)?;

        let (pte_paddr, pte_flags) = pte_flags(pte);

        if pte_flags & 1 == 0 {
            return Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: Some(pdpt_base),
                pd: Some(pd_base),
                pt: Some(pt_base),
                gpa: None,
                size: None,
            })
        }

        let gpa = pte_paddr + page_offset(gva);
        Ok(TranslatedAddress {
                pml4: Some(pml4_base),
                pdpt: Some(pdpt_base),
                pd: Some(pd_base),
                pt: Some(pt_base),
                gpa: Some(gpa),
                size: Some(GpaSize::Size4K),
            })
    }

    fn translate_gva_range(&self, cr3: Gpa, gva: Gva, size: usize) -> Result<BTreeSet<Gpa>, VirtMemError> {

        let mut pages = BTreeSet::new();
        for (base, _) in chunked(gva, size) {
            let translated = self.translate_gva_with_pages(cr3, base)?;
            let needed_pages = translated.needed_pages();
            pages.extend(needed_pages.iter());
        }

        Ok(pages)

    }
}

pub enum GpaSize {
    Size4K,
    Size2M,
    Size1G,
}

pub struct TranslatedAddress {
    pml4: Option<Gpa>,
    pdpt: Option<Gpa>,
    pd: Option<Gpa>,
    pt: Option<Gpa>,
    gpa: Option<Gpa>,
    size: Option<GpaSize>,
}


impl TranslatedAddress {

    pub fn is_valid(&self) -> bool {
        self.gpa.is_some()
    }

    pub fn needed_pages(&self) -> Vec<Gpa> {
        let mut pages = vec![];
        if let Some(gpa) = self.pml4 {
            pages.push(gpa);
        }

        if let Some(gpa) = self.pdpt {
            pages.push(gpa);
        }

        if let Some(gpa) = self.pd {
            pages.push(gpa);
        }

        if let Some(gpa) = self.pt {
            pages.push(gpa);
        }

        if let Some(gpa) = self.gpa {
            pages.push(gpa & !0xfff);
        }

        pages
    }

    pub fn size(&self) -> Option<&GpaSize> {
        self.size.as_ref()
    }

}

pub struct Allocator {
    pages: Vec<(usize, usize)>,
}

impl Allocator {
    pub fn new() -> Self {
        Self { pages: Vec::new() }
    }

    pub fn allocate_physical_memory(&mut self, size: usize) -> usize {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        let addr = ptr as usize;
        self.pages.push((addr, size));
        addr
    }
}

impl Default for Allocator {

    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Allocator {
    fn drop(&mut self) {
        debug!("destructing allocator");
        for &(addr, size) in &self.pages {
            let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
            let ptr = addr as *mut u8;
            unsafe { std::alloc::dealloc(ptr, layout) };
        }
    }
}

pub struct GpaManager {
    pub pages: FastMap64<u64, [u8; 4096]>,
}

impl GpaManager {
    pub fn new() -> Self {
        GpaManager {
            pages: FastMap64::default(),
        }
    }

    pub fn add_page(&mut self, gpa: Gpa, page: [u8; 4096]) {
        let (base, _) = page_off(gpa);
        self.pages.insert(base, page);
    }

    pub fn del_page(&mut self, gpa: Gpa) {
        let (base, _) = page_off(gpa);
        self.pages.remove(&base);
    }
}

impl Default for GpaManager {

    fn default() -> Self {
        Self::new()
    }
}

impl X64VirtualAddressSpace for GpaManager {
    fn read_gpa(&self, gpa: Gpa, buf: &mut [u8]) -> Result<(), VirtMemError> {
        if gpa + (buf.len() as Gpa) > (gpa & !0xfff) + 0x1000 {
            return Err(VirtMemError::SpanningPage);
        }

        let (base, off) = page_off(gpa);
        match self.pages.get(&base) {
            Some(arr) => {
                buf.copy_from_slice(&arr[off..off + buf.len()]);
                Ok(())
            }
            None => Err(VirtMemError::MissingPage(base)),
        }
    }

    fn write_gpa(&mut self, gpa: Gpa, data: &[u8]) -> Result<(), VirtMemError> {
        if gpa + (data.len() as Gpa) > (gpa & !0xfff) + 0x1000 {
            return Err(VirtMemError::SpanningPage);
        }

        let (base, off) = page_off(gpa);
        self.pages.entry(base).and_modify(|page| {
            let dst = &mut page[off..off + data.len()];
            dst.copy_from_slice(data);
        });

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum VirtMemError {
    Pml4eNotPresent,
    PdpteNotPresent,
    PdeNotPresent,
    PteNotPresent,
    SpanningPage,
    MissingPage(u64),
}

impl fmt::Display for VirtMemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for VirtMemError {
    fn description(&self) -> &str {
        "virtual to physical translation error"
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

pub fn chunked(start: Gva, sz: usize) -> impl Iterator<Item = (Gva, usize)> {
    debug_assert!(start.checked_add(sz as u64).is_some());

    let mut remaining = sz;
    let mut base = start;

    iter::from_fn(move || {
        if remaining == 0 {
            None
        } else {
            let chunk_base = base;

            let chunk_sz = if base as usize + remaining > (base as usize & !0xfff) + 0x1000 {
                ((base & !0xfff) + 0x1000 - base) as usize
            } else {
                remaining
            };

            base += chunk_sz as Gva;
            remaining -= chunk_sz;

            Some((chunk_base, chunk_sz))
        }
    })
}

#[test]
fn test_chunked() {
    let gva: Gva = 0xfffff;
    let mut iter = chunked(gva, 1);
    let a = iter.next();
    println!("{:?}", a);
    assert_eq!(a, Some((0xfffff, 1)));
    assert_eq!(iter.next(), None);

    let mut iter = chunked(gva, 2);
    assert_eq!(iter.next(), Some((0xfffff, 1)));
    assert_eq!(iter.next(), Some((0x100000, 1)));
    assert_eq!(iter.next(), None);
}