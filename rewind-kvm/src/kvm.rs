use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kvm_ioctls::VcpuExit;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

use kvm_bindings::{KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP, KVM_MAX_CPUID_ENTRIES, Msrs, kvm_guest_debug, kvm_guest_debug_arch, kvm_lapic_state, kvm_msr_entry, kvm_userspace_memory_region};
use kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES;

use rewind_core::mem::{self, VirtMemError, X64VirtualAddressSpace};
use rewind_core::snapshot::Snapshot;
use rewind_core::X64Snapshot;
use rewind_core::trace::{self, Context, CoverageMode, EmulationStatus, Params, ProcessorState, Trace, Tracer, TracerError};

const MSR_STAR: u32 = 0xC0000081;
const MSR_LSTAR: u32 = 0xC0000082;
const MSR_CSTAR: u32 = 0xC0000083;

const MSR_FS_BASE: u32 = 0xC0000100;
const MSR_GS_BASE: u32 = 0xC0000101;
const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;


/// Error
#[derive(Debug, thiserror::Error)]
pub enum KvmError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    IoctlError(#[from] kvm_ioctls::Error),
    #[error("{0}")]
    Generic(String),
    #[error("{0}")]
    KvmApiVersion(i32),
    #[error("{0:?}")]
    KvmCap(kvm_ioctls::Cap),
    #[error("{0}")]
    VmSetup(kvm_ioctls::Error),
}

type Gpa = u64;
type Hpa = u64;

#[derive(Debug, Default)]
struct RunState {
    pagefaults: usize,
    mapped_pages: Vec<Gpa>,
    stop_thread: bool,
    base_address: Hpa,
    breakpoints: Vec<Gpa>,
}

/// Kvm based tracer        
pub struct KvmTracer {
    // snapshot: SharedSnapshot<S>,
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    state: Arc<Mutex<RunState>>,
    snapshot: Arc<Mutex<dyn X64Snapshot>>,
    mem_regions: Vec<kvm_userspace_memory_region>,

}


impl KvmTracer
{
    /// Instanciate a tracer over a snapshot
    pub fn new<S>(snapshot: S) -> Result<Self, KvmError>
    where S: 'static + X64Snapshot + std::marker::Send
    {
        let kvm = Kvm::new()?;

        if kvm.get_api_version() != kvm_bindings::KVM_API_VERSION as i32 {
            return Err(KvmError::KvmApiVersion(kvm.get_api_version()));
        }

        // FIXME: reduce list
        use kvm_ioctls::Cap::*;
        // A list of KVM capabilities we want to check.
        let capabilities = vec![
            Irqchip,
            Ioeventfd,
            Irqfd,
            UserMemory,
            SetTssAddr,
            Pit2,
            PitState2,
            AdjustClock,
            Debugregs,
            MpState,
            VcpuEvents,
            Xcrs,
            Xsave,
            ExtCpuid,
            SyncRegs,
            ImmediateExit,
        ];

        // for c in capabilities {
        //     let check = !kvm.check_extension(c);
        //     if check {
        //         return Err(KvmError::KvmCap(c));
        //     }
        // }

        let max_memslots = kvm.get_nr_memslots();
        println!("max_memslots: {:x}", max_memslots);
        let vm_fd = kvm.create_vm()?;

        vm_fd.create_irq_chip().map_err(KvmError::VmSetup)?;

        println!("create vcpu");
        let vcpu_fd = vm_fd.create_vcpu(0)?;
        println!("created vcpu");

        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;

        vcpu_fd.set_cpuid2(&supported_cpuid)?;
 
        // let _supported_msrs = kvm.get_msr_index_list().map_err(KvmError::VmSetup)?.into_raw();

        // FIXME: read this from snapshot
        let mem_size: u64 = 0xc * 1024 * 1024 * 1024;
        println!("mem_size: {:x}", mem_size);

        let load_addr = unsafe {
            libc::mmap(
                null_mut(),
                mem_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            ) 
        };

        if load_addr == libc::MAP_FAILED {
            return Err(KvmError::KvmApiVersion(kvm.get_api_version()));
        }

        println!("load addr: {:x?}", load_addr);

        let uffd = UffdBuilder::new()
        .close_on_exec(true)
        .non_blocking(true)
        .create()
        .expect("uffd creation");

        uffd.register(load_addr, mem_size as usize).expect("uffd.register()");

        let state = Arc::new(Mutex::new(RunState::default()));
        state.lock().unwrap().base_address = load_addr as u64;

        // Create a thread that will process the userfaultfd events
        println!("starting uffd thread");
        let thread_state = state.clone();

        let snapshot = Arc::new(Mutex::new(snapshot));
        let thread_snapshot = snapshot.clone();
        let _s = std::thread::spawn(move || fault_handler_thread(uffd, thread_snapshot, thread_state));

        let mut guest_addr = 0;

        let apic_base: u64 = 0xfee00000;

        let mut mem_regions = Vec::new();
        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: guest_addr,
            memory_size: apic_base as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        println!("loading slot 0: {:x} - {:x}", mem_region.guest_phys_addr, mem_region.memory_size);
        unsafe { vm_fd.set_user_memory_region(mem_region)? };

        guest_addr += mem_region.memory_size + 0x1000;
        let size = mem_size - guest_addr;
        let hpa = mem_region.userspace_addr + guest_addr;

        mem_regions.push(mem_region);

        let mem_region = kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: guest_addr,
            memory_size: size,
            userspace_addr: hpa,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        println!("loading slot 1: {:x} - {:x}", mem_region.guest_phys_addr, mem_region.guest_phys_addr + mem_region.memory_size);
        unsafe { vm_fd.set_user_memory_region(mem_region)? };

        mem_regions.push(mem_region);

        // println!("set tss address");
        vm_fd.set_tss_address(KVM_TSS_ADDRESS as usize) .map_err(KvmError::VmSetup)?;

        // let dirty_pages_bitmap = vm_fd.get_dirty_log(slot, mem_size).unwrap();
        // println!("{:#x?}", dirty_pages_bitmap);
        // let klapic = vcpu_fd.get_lapic()?;
        // vcpu_fd.set_lapic(&klapic)?;

        let debug_struct = kvm_guest_debug {
            // Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
            // when encountering a software breakpoint during execution
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP,
            pad: 0,
            // Reset all x86-specific debug registers
            arch: kvm_guest_debug_arch {
                debugreg: [0, 0, 0, 0, 0, 0, 0, 0],
            },
        };

        vcpu_fd.set_guest_debug(&debug_struct).unwrap();

        Ok(Self { vcpu_fd, vm_fd, state, mem_regions, snapshot })
    }

    // FIXME: setup_demand_paging, setup_coverage_bp, populate_memory,

    fn enable_singlestep(&self) {
        let debug_struct = kvm_guest_debug {
            // Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
            // when encountering a software breakpoint during execution
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
            ..Default::default()
        };
        self.vcpu_fd.set_guest_debug(&debug_struct).unwrap();
    }

    // doesn't work, msr is disabled
    fn _enable_singlestep_on_branch(&self) {
        const MSR_DEBUG_CTL: u32 = 0x000001d9;
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: MSR_DEBUG_CTL,
                data: 1u64 << 1,
                ..Default::default()
            },
        ]).unwrap();

        let written = self.vcpu_fd.set_msrs(&msrs).map_err(|_|
            TracerError::UnknownError("set_msrs failed".into())
        ).unwrap();

        let mut vcpu_regs = self.vcpu_fd.get_regs().unwrap();
        vcpu_regs.rflags |= 0x100;
        self.vcpu_fd.set_regs(&vcpu_regs).unwrap();

    }

    fn get_context(&self) -> Result<Context, TracerError> {
        let vcpu_regs = self.vcpu_fd.get_regs().map_err(|_| TracerError::UnknownError("get_regs failed".into()))?;
        let context = Context {
            rax: vcpu_regs.rax,
            rbx: vcpu_regs.rbx,
            rcx: vcpu_regs.rcx,
            rdx: vcpu_regs.rdx,
            rsi: vcpu_regs.rsi,
            rdi: vcpu_regs.rdi,
            rsp: vcpu_regs.rsp,
            rbp: vcpu_regs.rbp,
            rflags: vcpu_regs.rflags,
            rip: vcpu_regs.rip,
            r8: vcpu_regs.r8,
            r9: vcpu_regs.r9,
            r10: vcpu_regs.r10,
            r11: vcpu_regs.r11,
            r12: vcpu_regs.r12,
            r13: vcpu_regs.r13,
            r14: vcpu_regs.r14,
            r15: vcpu_regs.r15,
        };
        Ok(context)
    }

    fn get_dirty_pages(&self) -> Result<Vec<u64>, TracerError> {
        let mut dirty_pages = Vec::new();
        for mem_region in self.mem_regions.iter() {

            let dirty_pages_bitmap = self.vm_fd.get_dirty_log(mem_region.slot, mem_region.memory_size as usize).unwrap();

            for (index, &bitmap) in dirty_pages_bitmap.iter().enumerate() {
                if bitmap == 0 {
                    continue
                }
                for bit_index in 0..64 {
                    let bit = (bitmap >> bit_index) & 1;
                    if bit == 0 {
                        continue
                    }

                    let gpa_index = index * 64 + bit_index;
                    let gpa = mem_region.guest_phys_addr as usize + gpa_index * 0x1000;

                    dirty_pages.push(gpa as u64);
                }
            }
        }
        // FIXME: will need snapshot to restore ...

        Ok(dirty_pages)
    }

    fn _get_dirty_pages(&self) -> Result<Vec<Gpa>, TracerError> {
        let mapped_pages = self.state.lock().unwrap().mapped_pages.clone();
        Ok(mapped_pages)
    }
}

impl Drop for KvmTracer {

    fn drop(&mut self) { 
        println!("dropped");
    }

}

pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
        | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffffu64) << 16)
        | (u64::from(limit) & 0x0000_ffffu64)
}

fn get_base(entry: u64) -> u64 {
    (((entry) & 0xFF00_0000_0000_0000) >> 32)
        | (((entry) & 0x0000_00FF_0000_0000) >> 16)
        | (((entry) & 0x0000_0000_FFFF_0000) >> 16)
}

fn get_limit(entry: u64) -> u32 {
    ((((entry) & 0x000F_0000_0000_0000) >> 32) | ((entry) & 0x0000_0000_0000_FFFF)) as u32
}

fn get_g(entry: u64) -> u8 {
    ((entry & 0x0080_0000_0000_0000) >> 55) as u8
}

fn get_db(entry: u64) -> u8 {
    ((entry & 0x0040_0000_0000_0000) >> 54) as u8
}

fn get_l(entry: u64) -> u8 {
    ((entry & 0x0020_0000_0000_0000) >> 53) as u8
}

fn get_avl(entry: u64) -> u8 {
    ((entry & 0x0010_0000_0000_0000) >> 52) as u8
}

fn get_p(entry: u64) -> u8 {
    ((entry & 0x0000_8000_0000_0000) >> 47) as u8
}

fn get_dpl(entry: u64) -> u8 {
    ((entry & 0x0000_6000_0000_0000) >> 45) as u8
}

fn get_s(entry: u64) -> u8 {
    ((entry & 0x0000_1000_0000_0000) >> 44) as u8
}

fn get_type(entry: u64) -> u8 {
    ((entry & 0x0000_0F00_0000_0000) >> 40) as u8
}

pub fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_bindings::kvm_segment {
    kvm_bindings::kvm_segment {
        base: get_base(entry),
        limit: get_limit(entry),
        selector: u16::from(table_index * 8),
        type_: get_type(entry),
        present: get_p(entry),
        dpl: get_dpl(entry),
        db: get_db(entry),
        s: get_s(entry),
        l: get_l(entry),
        g: get_g(entry),
        avl: get_avl(entry),
        padding: 0,
        unusable: match get_p(entry) {
            0 => 1,
            _ => 0,
        },
    }
}

impl Tracer for KvmTracer {
    // FIXME: not finished
    fn get_state(&mut self) -> Result<ProcessorState, TracerError> {
        let mut state = ProcessorState::default();
        let vcpu_sregs = self.vcpu_fd.get_sregs().map_err(|_| TracerError::UnknownError("get_sregs failed".into()))?;
        state.cs.base = vcpu_sregs.cs.base;

        let vcpu_regs = self.vcpu_fd.get_regs().map_err(|_| TracerError::UnknownError("get_regs failed".into()))?;
        state.rip = vcpu_regs.rip;
        Ok(state)
    }

    fn set_state(&mut self, context: &ProcessorState) -> Result<(), TracerError> {
        println!("set state");
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: MSR_STAR,
                data: context.star,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_LSTAR,
                data: context.lstar,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_CSTAR,
                data: context.cstar,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_FS_BASE,
                data: context.fs_base,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_GS_BASE,
                data: context.gs_base,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_KERNEL_GS_BASE,
                data: context.kernel_gs_base,
                ..Default::default()
            },
        ]).unwrap();

        let written = self.vcpu_fd.set_msrs(&msrs).map_err(|_|
            TracerError::UnknownError("set_msrs failed".into())
        )?;

        println!("wrote {} msr(s)", written);

        let mut vcpu_regs = self.vcpu_fd.get_regs().map_err(|_| TracerError::UnknownError("get_regs failed".into()))?;
        vcpu_regs.rax = context.rax;
        vcpu_regs.rbx = context.rbx;
        vcpu_regs.rcx = context.rcx;
        vcpu_regs.rdx = context.rdx;
        vcpu_regs.rsi = context.rsi;
        vcpu_regs.rdi = context.rdi;
        vcpu_regs.rsp = context.rsp;
        vcpu_regs.rbp = context.rbp;
        vcpu_regs.rflags = context.rflags;
        vcpu_regs.rip = context.rip;
        vcpu_regs.r8 = context.r8;
        vcpu_regs.r9 = context.r9;
        vcpu_regs.r10 = context.r10;
        vcpu_regs.r11 = context.r11;
        vcpu_regs.r12 = context.r12;
        vcpu_regs.r13 = context.r13;
        vcpu_regs.r14 = context.r14;
        vcpu_regs.r15 = context.r15;

        self.vcpu_fd.set_regs(&vcpu_regs).map_err(|e| {
            let msg = format!("set_regs failed: {}", e);
            TracerError::UnknownError(msg)
        })?;

        let mut vcpu_sregs = self.vcpu_fd.get_sregs().map_err(|_| TracerError::UnknownError("get_sregs failed".into()))?;

        let entry = gdt_entry(context.cs.flags, context.cs.base as u32, context.cs.limit);
        vcpu_sregs.cs = kvm_segment_from_gdt(entry, (context.cs.selector / 8) as u8);
        
        let entry = gdt_entry(context.ss.flags, context.ss.base as u32, context.ss.limit);
        vcpu_sregs.ss = kvm_segment_from_gdt(entry, (context.ss.selector / 8) as u8);

        let entry = gdt_entry(context.ds.flags, context.ds.base as u32, context.ds.limit);
        vcpu_sregs.ds = kvm_segment_from_gdt(entry, (context.ds.selector / 8) as u8);

        let entry = gdt_entry(context.es.flags, context.es.base as u32, context.es.limit);
        vcpu_sregs.es = kvm_segment_from_gdt(entry, (context.es.selector / 8) as u8);

        let entry = gdt_entry(context.fs.flags, context.fs.base as u32, context.fs.limit);
        vcpu_sregs.fs = kvm_segment_from_gdt(entry, (context.fs.selector / 8) as u8);
        vcpu_sregs.fs.base = context.fs_base;

        let entry = gdt_entry(context.gs.flags, context.gs.base as u32, context.gs.limit);
        vcpu_sregs.gs = kvm_segment_from_gdt(entry, (context.gs.selector / 8) as u8);
        vcpu_sregs.gs.base = context.gs_base;

        // FIXME: need to read them from snapshot
        let entry = gdt_entry(0x8b, 0x1cadd000, 0x67);
        vcpu_sregs.tr = kvm_segment_from_gdt(entry, (0x40 / 8) as u8);

        let entry = gdt_entry(0, 0, 0);
        vcpu_sregs.ldt = kvm_segment_from_gdt(entry, (0x0 / 8) as u8);

        vcpu_sregs.gdt.base = context.gdtr;
        vcpu_sregs.gdt.limit = context.gdtl;

        vcpu_sregs.idt.base = context.idtr;
        vcpu_sregs.idt.limit = context.idtl;

        vcpu_sregs.cr0 = context.cr0;
        vcpu_sregs.cr3 = context.cr3;
        vcpu_sregs.cr4 = context.cr4;
        vcpu_sregs.cr8 = context.cr8;

        vcpu_sregs.efer = context.efer;
        vcpu_sregs.apic_base = context.apic_base;

        self.vcpu_fd.set_sregs(&vcpu_sregs).map_err(|e| {
            let msg = format!("set_sregs failed: {}", e);
            TracerError::UnknownError(msg)
        })?;

        Ok(())
    }

    fn run<H: trace::Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace, TracerError> {
        let cr3 = self.snapshot.lock().unwrap().get_cr3();
        let gpa = self.snapshot.lock().unwrap().translate_gva(cr3, params.return_address)?;

        self.state.lock().unwrap().breakpoints.push(gpa);

        for (_, &gva) in params.excluded_addresses.iter() {
            let gpa = self.snapshot.lock().unwrap().translate_gva(cr3, gva)?;
            self.state.lock().unwrap().breakpoints.push(gpa);
        }

        if params.coverage_mode == CoverageMode::Instrs {
            self.enable_singlestep();
        }

        let mut trace = Trace::new();
        let context = self.get_context()?;
        trace.seen.insert(context.rip);
        if params.save_context {
            trace.coverage.push((context.rip, Some(context)));

        } else {
            trace.coverage.push((context.rip, None));
        }

        hook.setup(self);
        trace.start = Some(Instant::now());
        loop {
            match self.vcpu_fd.run().map_err(|_| TracerError::UnknownError("vcpu run failed".into()))? {
                VcpuExit::IoIn(addr, data) => {
                    println!(
                        "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                        addr, data[0],
                    );
                }
                VcpuExit::IoOut(addr, data) => {
                    println!(
                        "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                        addr, data[0],
                    );
                }
                VcpuExit::MmioRead(addr, data) => {
                    println!(
                        "Received an MMIO Read Request for the address {:#x}. Data: {:#x}",
                        addr, data[0],
                    );
                }
                VcpuExit::MmioWrite(addr, data) => {
                    println!(
                        "Received an MMIO Write Request to the address {:#x}. Data: {:#x}",
                        addr, data[0],
                    );
                }
                VcpuExit::Hlt => {
                    println!("Got Htl instruction");
                    break;
                }
                VcpuExit::Debug(event) => {
                    // println!("exception {} at {:x}", event.exception, event.pc);
                    if event.pc == params.return_address {
                        println!("got return address");
                        trace.status = EmulationStatus::Success;
                        break;
                    }

                    trace.seen.insert(event.pc);
                    if params.save_context {
                        let context = self.get_context()?;
                        trace.coverage.push((event.pc, Some(context)));
                    } else {
                        trace.coverage.push((event.pc, None));
                    }
                    // FIXME: set forbidden addresses
                }
                r => {
                    let vcpu_regs = self.vcpu_fd.get_regs().unwrap();
                    println!("{:#x?}", vcpu_regs);
                    let vcpu_sregs = self.vcpu_fd.get_sregs().unwrap();
                    println!("{:#x?}", vcpu_sregs);
                    println!("{:#x?}", self.state.lock().unwrap());
                    panic!("Unexpected exit reason: {:?}", r);
                }
            }
        }
        trace.end = Some(Instant::now());
        Ok(trace)
    }

    fn restore_snapshot(&mut self) -> Result<usize, TracerError> {
        use std::ops::Deref;
        // dirty pages is not working, restoring all pages :(
        let pages = self.get_dirty_pages()?;
        // bad clone
        // let pages = self.state.lock().unwrap().mapped_pages.clone();
        for &gpa in pages.iter() {
            let mut data = vec![0u8; 0x1000];
            Snapshot::read_gpa(self.snapshot.lock().unwrap().deref(), gpa, &mut data).map_err(|e| {
                TracerError::UnknownError(e.to_string())
            })?;
            self.write_gpa(gpa, &data)?;
        }
        // clean dirty log
        Ok(pages.len())
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError> {
        mem::X64VirtualAddressSpace::read_gva(self, cr3, vaddr, data).map_err(TracerError::VirtMemError)
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError> {
        mem::X64VirtualAddressSpace::write_gva(self, cr3, vaddr, data).map_err(TracerError::VirtMemError)
    }

    fn cr3(&mut self) -> Result<u64, TracerError> {
        todo!()
    }

    fn singlestep<H: trace::Hook>(
        &mut self,
        _params: &Params,
        _hook: &mut H,
    ) -> Result<Trace, TracerError> {
        todo!()
    }

    fn add_breakpoint(&mut self, _address: u64) {
        todo!()
    }

    fn get_mapped_pages(&self) -> Result<usize, TracerError> {
        let pagefaults = self.state.lock().unwrap().pagefaults;
        Ok(pagefaults)
    }
}

impl mem::X64VirtualAddressSpace for KvmTracer {
    fn read_gpa(&self, address: u64, data: &mut [u8]) -> Result<(), VirtMemError> {
        let base = self.state.lock().unwrap().base_address;
        let hpa = base + address;

        let buffer = unsafe { std::slice::from_raw_parts_mut(hpa as *mut u8, data.len()) };
        data.copy_from_slice(buffer);
 
        Ok(())
    }

    fn write_gpa(&mut self, address: u64, data: &[u8]) -> Result<(), VirtMemError> {
        let base = self.state.lock().unwrap().base_address;
        let hpa = base + address;

        let buffer = unsafe { std::slice::from_raw_parts_mut(hpa as *mut u8, data.len()) };
        buffer.copy_from_slice(data);
 
        Ok(())
 
    }
}

use libc::{self, c_void};
use std::os::unix::io::AsRawFd;
use userfaultfd::{Event, Uffd, UffdBuilder};
use nix::poll::{poll, PollFd, PollFlags};

fn fault_handler_thread<S: Snapshot + std::marker::Send>(uffd: Uffd, snapshot: Arc<Mutex<S>>, state: Arc<Mutex<RunState>>) {
    let page_size = 0x1000;

    // Create a page that will be copied into the faulting region
    let page = unsafe {
        libc::mmap(
            null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };

    let base = state.lock().unwrap().base_address as usize;
    // Loop, handling incoming events on the userfaultfd file descriptor
    loop {
        // FIXME: will not work
        if state.lock().unwrap().stop_thread {
            println!("stopping thread");
            break
        }

        let pollfd = PollFd::new(uffd.as_raw_fd(), PollFlags::POLLIN);
        let _nready = poll(&mut [pollfd], -1).expect("poll");

        let _revents = pollfd.revents().unwrap();

        let event = uffd
            .read_event()
            .expect("read uffd_msg")
            .expect("uffd_msg ready");

        if let Event::Pagefault { addr, .. } = event {
            let hpa = addr as usize;
            let gpa = hpa - base;

            let mut buffer = unsafe { std::slice::from_raw_parts_mut(page as *mut u8, page_size) };
            snapshot.lock().unwrap().read_gpa(gpa as u64, &mut buffer).expect(&format!("can't read gpa {:x}", gpa));

            state.lock().unwrap().pagefaults += 1;
            for &target_gpa in state.lock().unwrap().breakpoints.iter() {
                if (target_gpa as usize) >= gpa && (target_gpa as usize) < gpa + 0x1000 {
                    // println!("patching return address");
                    let offset = (target_gpa & 0xfff) as usize;
                    buffer[offset] = 0xcc;
                }
            }

            let dst = (addr as usize & !(page_size as usize - 1)) as *mut c_void;
            let _copy = unsafe { uffd.copy(page, dst, page_size, true).expect("uffd copy") };

            state.lock().unwrap().mapped_pages.push(gpa as Gpa);
        } else {
            panic!("Unexpected event on userfaultfd");
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use kvm_bindings::{KVM_MAX_CPUID_ENTRIES, kvm_segment};
    use mem::X64VirtualAddressSpace;
    use pretty_hex::PrettyHex;
    use rewind_snapshot::FileSnapshot;

    use super::*;

    #[derive(Default)]
    struct TestHook {

    }

    impl trace::Hook for TestHook {
        fn setup<T: trace::Tracer>(&mut self, _tracer: &mut T) {

        }

        fn handle_breakpoint<T: trace::Tracer>(&mut self, _tracer: &mut T) -> Result<bool, trace::TracerError> {
            todo!()
        }

        fn handle_trace(&self, _trace: &mut trace::Trace) -> Result<bool, trace::TracerError> {
            Ok(true)
        }

        fn patch_page(&self, _: u64) -> bool {
            todo!()
        }
    }

    #[test]
    fn test_tracer() {

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();

        // let gpa = snapshot.translate_gva(context.cr3, return_address).unwrap();
        // println!("gpa is {:x}", gpa);

        let mut tracer = KvmTracer::new(snapshot).unwrap();
        
        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = return_address;
        params.save_context = true;

        tracer.set_state(&context).unwrap();
        tracer.enable_singlestep();

        let trace = tracer.run(&params, &mut hook).unwrap();
        println!("trace lasted {:?}", trace.end.unwrap() - trace.start.unwrap());

        let pagefaults = tracer.get_mapped_pages().unwrap();
        println!("got {} pagefault(s)", pagefaults);
        assert_eq!(pagefaults, 130);

        let modified_pages = tracer.get_dirty_pages().unwrap();
        assert_eq!(modified_pages.len(), 130);

        // let modified_pages = tracer.get_dirty_pages().unwrap();
        // assert_eq!(modified_pages.len(), 0);

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);

        let expected = Trace::load(path.join("trace.json")).unwrap();

        assert_eq!(trace.seen.len(), expected.seen.len());
        assert_eq!(trace.coverage.len(), expected.coverage.len());

        assert_eq!(trace.status, trace::EmulationStatus::Success);

        assert_eq!(trace.coverage[0].0, context.rip);

        for (index, (addr, context)) in expected.coverage.iter().enumerate() {
            assert_eq!(*addr, trace.coverage[index].0, "index {}: rip {:x} vs {:x}", index, *addr, trace.coverage[index].0);
            if let Some(context) = context {
                let expected_context = trace.coverage[index].1.as_ref().unwrap();
                // rflags are different so they are not tested
                assert_eq!(context.rax, expected_context.rax);
                assert_eq!(context.rbx, expected_context.rbx);
                assert_eq!(context.rcx, expected_context.rcx);
                assert_eq!(context.rdx, expected_context.rdx);
                assert_eq!(context.rsi, expected_context.rsi);
                assert_eq!(context.rdi, expected_context.rdi);
                assert_eq!(context.rsp, expected_context.rsp);
                assert_eq!(context.rbp, expected_context.rbp);
                assert_eq!(context.r8, expected_context.r8);
                assert_eq!(context.r9, expected_context.r9);
                assert_eq!(context.r10, expected_context.r10);
                assert_eq!(context.r11, expected_context.r11);
                assert_eq!(context.r12, expected_context.r12);
                assert_eq!(context.r13, expected_context.r13);
                assert_eq!(context.r14, expected_context.r14);
                assert_eq!(context.r15, expected_context.r15);
                assert_eq!(context.rip, expected_context.rip, "rip");
                assert_eq!(*addr, expected_context.rip, "rip");

            }

            assert!(expected.seen.contains(addr));
            assert!(trace.seen.contains(addr));

        }

    }

    #[test]
    fn test_read_write_mem() {

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();

        let gpa = snapshot.translate_gva(context.cr3, return_address).unwrap();
        println!("gpa is {:x}", gpa);

        let mut tracer = KvmTracer::new(snapshot).unwrap();
        
        let data = &[0xcc];
        Tracer::write_gva(&mut tracer, context.cr3, return_address, data).unwrap();

        let mut expected = vec![0u8; 10];
        Tracer::read_gva(&mut tracer, context.cr3, return_address, &mut expected).unwrap();

        assert_eq!(expected, [0xcc, 0x8d, 0x9c, 0x24, 0xa0, 0, 0, 0, 0x49, 0x8b]);

        // let modified_pages = tracer.restore_snapshot().unwrap();
        // assert_eq!(modified_pages, 5);

    }

    fn prefix_lines(prefix: &str, lines: &str) -> String {
        lines
            .lines()
            .map(|i| [prefix, i].concat())
            .collect::<Vec<String>>()
            .join("\n")
    }

    pub struct Diff(difference::Changeset);

    impl Diff {
        pub fn new(left: &str, right: &str) -> Self {
            Self(difference::Changeset::new(left, right, "\n"))
        }
    }

    impl std::fmt::Display for Diff {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            for d in &self.0.diffs {
                match *d {
                    difference::Difference::Same(ref _x) => {
                        // write!(f, "{}{}", prefix_lines(" ", x), self.0.split)?;
                    }
                    difference::Difference::Add(ref x) => {
                        write!(f, "\x1b[92m{}\x1b[0m{}", prefix_lines("+", x), self.0.split)?;
                    }
                    difference::Difference::Rem(ref x) => {
                        write!(f, "\x1b[91m{}\x1b[0m{}", prefix_lines("-", x), self.0.split)?;
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn test_dirty_log() {
        use pretty_assertions::assert_eq;
        use pretty_hex::*;

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let mut tracer = KvmTracer::new(snapshot).unwrap();

        let modified_pages = tracer.restore_snapshot().unwrap();
        assert_eq!(modified_pages, 0);

        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = 0xfffff8051b28643c;
        params.save_context = true;

        tracer.set_state(&context).unwrap();
        tracer.enable_singlestep();

        let trace = tracer.run(&params, &mut hook).unwrap();
        println!("trace lasted {:?}", trace.end.unwrap() - trace.start.unwrap());

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);
        assert_eq!(trace.seen.len(), 7);
        assert_eq!(trace.coverage.len(), 7);
        assert_eq!(trace.status, trace::EmulationStatus::Success);

        let mut mapped_pages = tracer.get_dirty_pages().unwrap();
        assert_eq!(mapped_pages.len(), 9);
    
        let mut expected_pages = [0x235500000,
                                      0x3a08000,
                                      0x3a09000,
                                      0x3a18000,
                                      0x237f32000,
                                      0xb0c000,
                                      0xb0d000,
                                      0x20c7d8000,
                                      0x125a3d000];

        assert_eq!(mapped_pages.sort(), expected_pages.sort());

        let snapshot = FileSnapshot::new(&path).unwrap();

        let mut diff_count = 0;
        for &gpa in expected_pages.iter() {
            let mut orig = vec![0u8; 0x1000];
            Snapshot::read_gpa(&snapshot, gpa, &mut orig).unwrap();
            let mut modified = vec![0u8; 0x1000];
            tracer.read_gpa(gpa, &mut &mut modified).unwrap();
            let orig_hex = pretty_hex(&orig);
            let modified_hex = pretty_hex(&modified);
            let diff = Diff::new(&orig_hex, &modified_hex);
            let diff_string = format!("{}", diff);
            if !diff_string.is_empty() {
                println!("diff for {:x}", gpa);
                println!("{}", diff);
                diff_count += 1;
            }
        }

        assert_eq!(diff_count, 2);
        let modified_pages = tracer.restore_snapshot().unwrap();
        // FIXME: it should be 2 ...
        assert_eq!(modified_pages, 9);
    }

    #[test]
    fn test_dirty_log2() {
        use pretty_assertions::assert_eq;
        use pretty_hex::*;

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let mut tracer = KvmTracer::new(snapshot).unwrap();

        let mut expected = vec![0u8; 10];
        Tracer::read_gva(&mut tracer, context.cr3, context.rip, &mut expected).unwrap();

        dbg!(expected);

        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = 0xfffff8051b28643c;
        params.save_context = true;

        tracer.set_state(&context).unwrap();
        tracer.enable_singlestep();

        let trace = tracer.run(&params, &mut hook).unwrap();
        println!("trace lasted {:?}", trace.end.unwrap() - trace.start.unwrap());

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);
        assert_eq!(trace.seen.len(), 7);
        assert_eq!(trace.coverage.len(), 7);
        assert_eq!(trace.status, trace::EmulationStatus::Success);

        let mut mapped_pages = tracer._get_dirty_pages().unwrap();
        assert_eq!(mapped_pages.len(), 9);
        println!("{:#x?}", mapped_pages);
    
        let mut expected_pages = [0x235500000,
                                      0x3a08000,
                                      0x3a09000,
                                      0x3a18000,
                                      0x237f32000,
                                      0xb0c000,
                                      0xb0d000,
                                      0x20c7d8000,
                                      0x125a3d000];

        assert_eq!(mapped_pages.sort(), expected_pages.sort());

        tracer.set_state(&context).unwrap();
        tracer.enable_singlestep();
        let trace = tracer.run(&params, &mut hook).unwrap();

        let mapped_pages = tracer.get_dirty_pages().unwrap();
        println!("{:#x?}", mapped_pages);
        assert_eq!(mapped_pages.len(), 9);

        let snapshot = FileSnapshot::new(&path).unwrap();

        let mut diff_count = 0;
        for &gpa in expected_pages.iter() {
            let mut orig = vec![0u8; 0x1000];
            Snapshot::read_gpa(&snapshot, gpa, &mut orig).unwrap();
            let mut modified = vec![0u8; 0x1000];
            tracer.read_gpa(gpa, &mut &mut modified).unwrap();
            let orig_hex = pretty_hex(&orig);
            let modified_hex = pretty_hex(&modified);
            let diff = Diff::new(&orig_hex, &modified_hex);
            let diff_string = format!("{}", diff);
            if !diff_string.is_empty() {
                println!("diff for {:x}", gpa);
                println!("{}", diff);
                diff_count += 1;
            }
        }

        assert_eq!(diff_count, 1);
        let mapped_pages = tracer.get_dirty_pages().unwrap();
        // FIXME: it should be 2 ...
        assert_eq!(mapped_pages.len(), 0);
    }


    #[test]
    fn test_trace_msr() {

        let path = std::path::PathBuf::from("../examples/CVE-2020-17087/snapshots/17763.1.amd64fre.rs5_release.180914-1434/cng/ConfigIoHandler_Safeguarded");
        let snapshot = FileSnapshot::new(&path).unwrap();

        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();

        let return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();

        let mut tracer = KvmTracer::new(snapshot).unwrap();
        
        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = return_address;
        params.save_context = true;

        tracer.set_state(&context).unwrap();

        tracer._enable_singlestep_on_branch();
        // tracer.enable_singlestep();

        let trace = tracer.run(&params, &mut hook).unwrap();
        println!("trace lasted {:?}", trace.end.unwrap() - trace.start.unwrap());

        let pagefaults = tracer.get_mapped_pages().unwrap();
        println!("got {} pagefault(s)", pagefaults);
        assert_eq!(pagefaults, 130);

        let modified_pages = tracer.get_dirty_pages().unwrap();
        assert_eq!(modified_pages.len(), 130);

        assert_eq!(trace.seen.len(), 3176);
        assert_eq!(trace.coverage.len(), 34174);

        assert_eq!(trace.status, trace::EmulationStatus::Success);


    }


    #[test]
    fn test_basic() {
        use kvm_ioctls::{Kvm, VmFd, VcpuFd};
        use kvm_ioctls::VcpuExit;

        use std::io::Write;
        use std::slice;
        use std::ptr::null_mut;

        use kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES;
        use kvm_bindings::kvm_userspace_memory_region;

        let mem_size = 0x4000;
        let guest_addr = 0x1000;
        let asm_code: &[u8];

        // Setting up architectural dependent values.
        asm_code = &[
            0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
            0x00, 0xd8, /* add %bl, %al */
            0x04, b'0', /* add $'0', %al */
            0xee, /* out %al, %dx */
            0xec, /* in %dx, %al */
            0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
            0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
            0xf4, /* hlt */
        ];

        // 1. Instantiate KVM.
        let kvm = Kvm::new().unwrap();

        // 2. Create a VM.
        let vm = kvm.create_vm().unwrap();

        // 3. Initialize Guest Memory.
        let load_addr: *mut u8 = unsafe {
            libc::mmap(
                null_mut(),
                mem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            ) as *mut u8
        };

        let slot = 0;
        // When initializing the guest memory slot specify the
        // `KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe { vm.set_user_memory_region(mem_region).unwrap() };

        // Write the code in the guest memory. This will generate a dirty page.
        unsafe {
            let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write(&asm_code).unwrap();
        }

        // 4. Create one vCPU.
        let vcpu_fd = vm.create_vcpu(0).unwrap();

        // 5. Initialize general purpose and special registers.
        // x86_64 specific registry setup.
        let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd.set_regs(&vcpu_regs).unwrap();

        // 6. Run code on the vCPU.
        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    println!(
                        "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                        addr,
                        data[0],
                    );
                }
                VcpuExit::IoOut(addr, data) => {
                    println!(
                        "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                        addr,
                        data[0],
                    );
                }
                VcpuExit::MmioRead(addr, data) => {
                    println!(
                        "Received an MMIO Read Request for the address {:#x}.",
                        addr,
                    );
                }
                VcpuExit::MmioWrite(addr, data) => {
                    println!(
                        "Received an MMIO Write Request to the address {:#x}.",
                        addr,
                    );
                    // The code snippet dirties 1 page when it is loaded in memory
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .fold(0, |dirty_page_count, i| dirty_page_count + i);
                    assert_eq!(dirty_pages, 1);
                }
                VcpuExit::Hlt => {
                    break;
                }
                r => panic!("Unexpected exit reason: {:?}", r),
            }
        }
    }

    bitflags::bitflags! {
        struct Cr0: u64 {
            const PE = 0b0000_0001;
            const MP = 0b0000_0010;
            const EM = 0b0000_0100;
            const TS = 0b0000_1000;
            const ET = 0b0001_0000;
            const NE = 0b0010_0000;
            const WP = 0b0001_0000_0000_0000_0000;
            const AM = 0b0100_0000_0000_0000_0000;
            const NW = 0b0010_0000_0000_0000_0000_0000_0000_0000;
            const CD = 0b0100_0000_0000_0000_0000_0000_0000_0000;
            const PG = 0b1000_0000_0000_0000_0000_0000_0000_0000;
        }

        struct Cr4: u64 {
            const VME = 0b0000_0000_0000_0000_0000_0000_0000_0001;
            const PVI = 0b0000_0000_0000_0000_0000_0000_0000_0010;
            const TSD = 0b0000_0000_0000_0000_0000_0000_0000_0100;
            const DE = 0b0000_0000_0000_0000_0000_0000_0000_1000;
            const PSE = 0b0000_0000_0000_0000_0000_0000_0001_0000;
            const PAE = 0b0000_0000_0000_0000_0000_0000_0010_0000;
            const MCE = 0b0000_0000_0000_0000_0000_0000_0100_0000;
            const PGE = 0b0000_0000_0000_0000_0000_0000_1000_0000;
            const PCE = 0b0000_0000_0000_0000_0000_0001_0000_0000;
            const OSFXSR = 0b0000_0000_0000_0000_0000_0010_0000_0000;
            const OSXMMEXCPT = 0b0000_0000_0000_0000_0000_0100_0000_0000;
            const UMIP = 0b0000_0000_0000_0000_0000_1000_0000_0000;
            const LA57 = 0b0000_0000_0000_0000_0001_0000_0000_0000;
            const VMXE = 0b0000_0000_0000_0000_0010_0000_0000_0000;
            const SMXE = 0b0000_0000_0000_0000_0100_0000_0000_0000;
            const FSGSBASE = 0b0000_0000_0000_0001_0000_0000_0000_0000;
            const PCIDE = 0b0000_0000_0000_0010_0000_0000_0000_0000;
            const OSXSAVE = 0b0000_0000_0000_0100_0000_0000_0000_0000;
            const SMEP = 0b0000_0000_0001_0000_0000_0000_0000_0000;
            const SMAP = 0b0000_0000_0010_0000_0000_0000_0000_0000;
            const PKE = 0b0000_0000_0100_0000_0000_0000_0000_0000;
            const CET = 0b0000_0000_1000_0000_0000_0000_0000_0000;
            const PKS = 0b0000_0001_0000_0000_0000_0000_0000_0000;
        }
    }

    #[test]
    fn test_init_unicode_string() {
        let file = std::fs::File::open("RtlInitUnicodeString.json").unwrap();
        let data: serde_json::Value = serde_json::from_reader(file).unwrap();
        
        let kvm = Kvm::new().unwrap();

        let vm = kvm.create_vm().unwrap();
        vm.create_irq_chip().unwrap();

        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .unwrap();

        let cpuid = supported_cpuid.as_slice();
        for i in cpuid.iter() {
            // println!("{:#x?}", i);
        }

        // vm.set_tss_address(KVM_TSS_ADDRESS as usize).unwrap();

        let vcpu_fd = vm.create_vcpu(0).unwrap();

        vcpu_fd.set_cpuid2(&supported_cpuid).unwrap();
        // let cpuid = cpuid.as_slice();
        // for _i in cpuid.iter() {
        //     // println!("{:x}", _i.function);
        // }

        let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();

        let mut vcpu_regs = vcpu_fd.get_regs().unwrap();

        let regs = data["regs"].as_object().unwrap();
        for (reg, value) in regs {
            if reg == "rax"  {
                vcpu_regs.rax = value.as_u64().unwrap();
            } else if reg == "rbx" {
                vcpu_regs.rbx = value.as_u64().unwrap();
            } else if reg == "rbx" {
                vcpu_regs.rbx = value.as_u64().unwrap();
            } else if reg == "rcx" {
                vcpu_regs.rcx = value.as_u64().unwrap();
            } else if reg == "rdx" {
                vcpu_regs.rdx = value.as_u64().unwrap();
            } else if reg == "rsi" {
                vcpu_regs.rsi = value.as_u64().unwrap();
            } else if reg == "rdi" {
                vcpu_regs.rdi = value.as_u64().unwrap();
            } else if reg == "rbp" {
                vcpu_regs.rbp = value.as_u64().unwrap();
            } else if reg == "rsp" {
                vcpu_regs.rsp = value.as_u64().unwrap();
            } else if reg == "r8" {
                vcpu_regs.r8 = value.as_u64().unwrap();
            } else if reg == "r9" {
                vcpu_regs.r9 = value.as_u64().unwrap();
            } else if reg == "r10" {
                vcpu_regs.r10 = value.as_u64().unwrap();
            } else if reg == "r11" {
                vcpu_regs.r11 = value.as_u64().unwrap();
            } else if reg == "r12" {
                vcpu_regs.r12 = value.as_u64().unwrap();
            } else if reg == "r13" {
                vcpu_regs.r13 = value.as_u64().unwrap();
            } else if reg == "r14" {
                vcpu_regs.r14 = value.as_u64().unwrap();
            } else if reg == "r15" {
                vcpu_regs.r15 = value.as_u64().unwrap();
            } else if reg == "rip" {
                vcpu_regs.rip = value.as_u64().unwrap();
            } else if reg == "cr0" {
                vcpu_sregs.cr0 = value.as_u64().unwrap();
            } else if reg == "cr3" {
                vcpu_sregs.cr3 = value.as_u64().unwrap();
            } else if reg == "cr4" {
                vcpu_sregs.cr4 = value.as_u64().unwrap();
            } else if reg == "gdtr" {
                vcpu_sregs.gdt.base = value.as_u64().unwrap();
            } else if reg == "gdtl" {
                vcpu_sregs.gdt.limit = value.as_u64().unwrap() as u16;
            } else if reg == "idtr" {
                vcpu_sregs.idt.base = value.as_u64().unwrap();
            } else if reg == "idtl" {
                vcpu_sregs.idt.limit = value.as_u64().unwrap() as u16;
            } else if reg == "cs" {
                let selector = value.as_u64().unwrap() as u16;
                let flags = 0x209b;
                let base = 0;
                let limit = 0;
                let entry = gdt_entry(flags, base, limit);
                vcpu_sregs.cs = kvm_segment_from_gdt(entry, (selector / 8) as u8);
                vcpu_sregs.cs.type_ = 0x1b;
                vcpu_sregs.cs.s = 0;
            } else if reg == "ss" {
                let selector = value.as_u64().unwrap() as u16;
                let flags = 0x493;
                let base = 0;
                let limit = 0;
                let entry = gdt_entry(flags, base, limit);
                vcpu_sregs.ss = kvm_segment_from_gdt(entry, (selector / 8) as u8);
                vcpu_sregs.ss.type_ = 0x13;
                vcpu_sregs.ss.s = 0;
            } else if reg == "ds" {
                let selector = value.as_u64().unwrap() as u16;
                let flags = 0xcf3;
                let base = 0;
                let limit = 0xffffffff;
                let entry = gdt_entry(flags, base, limit);
                vcpu_sregs.ds = kvm_segment_from_gdt(entry, (selector / 8) as u8);
                vcpu_sregs.ds.type_ = 0x13;
            } else if reg == "es" {
                let selector = value.as_u64().unwrap() as u16;
                let flags = 0xcf3;
                let base = 0;
                let limit = 0xffffffff;
                let entry = gdt_entry(flags, base, limit);
                vcpu_sregs.es = kvm_segment_from_gdt(entry, (selector / 8) as u8);
                vcpu_sregs.es.type_ = 0x13;
            } else if reg == "fs" {
                let selector = value.as_u64().unwrap() as u16;
                let flags = 0x4f3;
                let base = 0;
                let limit = 0x3c00;
                let entry = gdt_entry(flags, base, limit);
                vcpu_sregs.fs = kvm_segment_from_gdt(entry, (selector / 8) as u8);
                vcpu_sregs.fs.type_ = 0x13;
            } else if reg == "gs" {
                let selector = value.as_u64().unwrap() as u16;
                let flags = 0xcf3;
                let base = 0;
                let limit = 0xffffffff;
                let entry = gdt_entry(flags, base, limit);
                vcpu_sregs.gs = kvm_segment_from_gdt(entry, (selector / 8) as u8);
                vcpu_sregs.gs.type_ = 0x13;
            }

        }

        vcpu_sregs.cs = kvm_segment {base: 0, limit: 4294967295, selector: 16, type_: 11, present:1, dpl:0, db:0, s:1, l:1, g:1, avl:0, padding: 0, unusable: 0};

        vcpu_sregs.ds = kvm_segment {base: 0, limit: 4294967295, selector: 43, type_: 3, present:1, dpl:3, db:0, s:1, l:1, g:1, avl:0, padding: 0, unusable: 0};
        vcpu_sregs.es = kvm_segment {base: 0, limit: 4294967295, selector: 43, type_: 3, present:1, dpl:3, db:0, s:1, l:1, g:1, avl:0, padding: 0, unusable: 0};
        vcpu_sregs.fs = kvm_segment {base: 0, limit: 4294967295, selector: 83, type_: 3, present:1, dpl:3, db:0, s:1, l:1, g:1, avl:0, padding: 0, unusable: 0};
        vcpu_sregs.ss = kvm_segment {base: 0, limit: 4294967295, selector: 43, type_: 3, present:1, dpl:3, db:0, s:1, l:1, g:1, avl:0, padding: 0, unusable: 0};
        vcpu_sregs.gs = kvm_segment {base: 0xdfd9621000, limit: 4294967295, selector: 43, type_: 3, present:1, dpl:3, db:0, s:1, l:1, g:1, avl:0, padding: 0, unusable: 0};
        vcpu_sregs.tr = kvm_segment {base: 0xfffff8047375c000, limit: 103, selector: 64, type_: 11, present:1, dpl:0, db:0, s:0, l:0, g:0, avl:0, padding: 0, unusable: 0};
        vcpu_sregs.ldt = kvm_segment {base: 0, limit: 0, selector: 0, type_: 0, present:0, dpl:0, db:0, s:0, l:0, g:0, avl:0, padding: 0, unusable: 0};

        let efer = data["efer"].as_u64().unwrap();
        vcpu_sregs.efer = efer;
        println!("efer {:x}", vcpu_sregs.efer);

        let wtf_cr0 = 0x80050033;
        let cr0 = Cr0::from_bits(wtf_cr0).unwrap();
        println!("wtf cr0 {:x} {:#x?}", wtf_cr0, cr0);

        let cr0 = Cr0::from_bits(vcpu_sregs.cr0).unwrap();
        // println!("cr0 {:x} {:#x?}", vcpu_sregs.cr0, cr0);
        vcpu_sregs.cr0 = wtf_cr0;

        let wtf_cr4 = 0x3506f8;
        let cr4 = Cr4::from_bits(wtf_cr4).unwrap();
        // println!("wtf cr4 {:x} {:#x?}", wtf_cr4, cr4);

        let cr4 = Cr4::from_bits(vcpu_sregs.cr4).unwrap();
        // println!("cr4 {:x} {:#x?}", vcpu_sregs.cr4, cr4);
        vcpu_sregs.cr4 = wtf_cr4;

        vcpu_sregs.cr3 = vcpu_sregs.cr3 &!0xfff;
        // println!("cr3 {:x}", vcpu_sregs.cr3);

        let _return_addr = data["return_address"].as_u64().unwrap();

        let entry = gdt_entry(0x8b, 0x1cadd000, 0x67);
        vcpu_sregs.tr = kvm_segment_from_gdt(entry, (0x40 / 8) as u8);
        vcpu_sregs.tr.base = 0xfffff8051cadd000;

        let entry = gdt_entry(0, 0, 0);
        vcpu_sregs.ldt = kvm_segment_from_gdt(entry, (0x0 / 8) as u8);
        // let mem_size = 0x706e9000usize;
        let mem_size = 4429185024usize;

        let load_addr: *mut u8 = unsafe {
            libc::mmap(
                null_mut(),
                mem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE, // | libc::MAP_NORESERVE,
                -1,
                0,
            ) as *mut u8
        };

        if load_addr == libc::MAP_FAILED as *mut u8 {
            panic!("mmap failed");
        }

        let mut guest_addr = 0;

        let apic_base: u64 = 0xfee00000;

        let mut mem_regions = Vec::new();
        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: guest_addr,
            memory_size: apic_base as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        println!("loading slot 0: {:x} - {:x}", mem_region.guest_phys_addr, mem_region.memory_size);
        unsafe { vm.set_user_memory_region(mem_region).unwrap() };

        guest_addr += mem_region.memory_size + 0x1000;
        let size = mem_size as u64 - guest_addr;
        let hpa = mem_region.userspace_addr + guest_addr;

        mem_regions.push(mem_region);

        let mem_region = kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: guest_addr,
            memory_size: size,
            userspace_addr: hpa,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        println!("loading slot 1: {:x} - {:x}", mem_region.guest_phys_addr, mem_region.guest_phys_addr + mem_region.memory_size);
        unsafe { vm.set_user_memory_region(mem_region).unwrap() };

        mem_regions.push(mem_region);

        let pfns = data["pfn"].as_object().unwrap();
        for (index, (pfn, data)) in pfns.iter().enumerate() {
            let pfn = u64::from_str_radix(pfn, 10).unwrap();
            let value = data.as_str().unwrap();
            let data = base64::decode(value).unwrap();

            let gpa = pfn * 0x1000;
            let slot = index as u32;

            let offset = load_addr as usize + gpa as usize;

            println!("writing pfn {:x} to slot {:x}, hpa: {:x}", pfn, slot, offset);

            unsafe {
                let slice = std::slice::from_raw_parts_mut(offset as *mut u8, 0x1000);
                slice.copy_from_slice(&data);

                assert_eq!(slice, &data);
            } 


        }
        struct Blah {
            base_address: u64,
        }

        impl mem::X64VirtualAddressSpace for Blah {
            fn read_gpa(&self, address: u64, data: &mut [u8]) -> Result<(), VirtMemError> {
                let base = self.base_address;
                let hpa = base + address;

                let buffer = unsafe { std::slice::from_raw_parts_mut(hpa as *mut u8, data.len()) };
                data.copy_from_slice(buffer);
        
                Ok(())
            }

            fn write_gpa(&mut self, address: u64, data: &[u8]) -> Result<(), VirtMemError> {
                Ok(())
        
            }
        }


        let b = Blah {base_address: load_addr as u64};

        let a = b.translate_gva(vcpu_sregs.cr3, vcpu_regs.rip).unwrap();
        println!("rip translate to {:x}", a);
        let mut data = vec![0u8; 0x10];
        b.read_gva(vcpu_sregs.cr3, vcpu_regs.rip, &mut data).unwrap();

        println!("{:?}", data.hex_dump());

        // let mut cap: kvm_bindings::kvm_enable_cap = Default::default();
        // cap.cap = kvm_bindings::KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2;
        // vm.enable_cap(&cap).unwrap();

        // let run_size = vm.run_size();
        // println!("run size {:x}", run_size);

        vcpu_regs.rflags = 0x206;
        vcpu_fd.set_regs(&vcpu_regs).expect("set_regs");

        let mut fpu = vcpu_fd.get_fpu().unwrap();
        fpu.mxcsr = 0x1f80;
        fpu.fcw = 0x27f;
        fpu.fsw = 0;
        fpu.last_opcode = 0;

        // println!("{:#x?}", fpu);
        vcpu_fd.set_fpu(&fpu).unwrap();

        // println!("{:#x?}", vcpu_sregs);
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: MSR_STAR,
                data: 0x23001000000000,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_LSTAR,
                data: 0xfffff8046f1cdc40,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_CSTAR,
                data: 0xfffff8046f1cd780,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_FS_BASE,
                data: 0,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_GS_BASE,
                data: 0,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_KERNEL_GS_BASE,
                data: 0xfffff8046b6f3000,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x277, //IA32_CR_PAT
                data: 0x7010600070106,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x1b,
                data: 0xfee00900, // APIC_BASE
                ..Default::default()
            },
        ]).unwrap();

        let written = vcpu_fd.set_msrs(&msrs).unwrap();
        println!("wrote {} msr(s)", written);

        // let xsave = vcpu_fd.get_xsave().unwrap();
        // println!("{:#x?}", xsave);

        // https://en.wikipedia.org/wiki/Control_register#XCR0_and_XSS
        let mut xc = vcpu_fd.get_xcrs().unwrap();
        xc.nr_xcrs = 1;
        xc.flags = 0;
        xc.xcrs[0].value = 0x1;
        // println!("{:#x?}", xc);
        vcpu_fd.set_xcrs(&xc).expect("set_xcrs");

        vcpu_fd.set_sregs(&vcpu_sregs).expect("set_sregs");

    }
}