
use std::convert::TryInto;
use std::collections::BTreeSet;
use std::time::Instant;

use rewind_core::mem::{self, VirtMemError};
use rewind_core::trace::{self, ProcessorState, Context, Params, Tracer, Trace, EmulationStatus, TracerError};
use rewind_core::snapshot::Snapshot;

use bochscpu::cpu::{Cpu, RunState, State, Seg, GlobalSeg};
use bochscpu::hook;
use bochscpu::mem as guest_mem;

struct LocalContext(Context);

impl From<State> for LocalContext {

    fn from(state: State) -> Self {
        let context = Context {
            rax: state.rax,
            rbx: state.rbx,
            rcx: state.rcx,
            rdx: state.rdx,
            rsp: state.rsp,
            rbp: state.rbp,
            rdi: state.rdi,
            rsi: state.rsi,
            r8: state.r8,
            r9: state.r9,
            r10: state.r10,
            r11: state.r11,
            r12: state.r12,
            r13: state.r13,
            r14: state.r14,
            r15: state.r15,
            rip: state.rip,
            rflags: state.rflags
        };
        LocalContext(context)
    }

}

// FIXME: only trace struct
#[derive(Debug)]
struct BochsHooks <'a, S: Snapshot>{
    singlestep: bool,
    // return_address: u64,
    // excluded_addresses: HashMap<String, u64>,
    instructions_count: u64,
    // limit: u64,
    // coverage: Vec<(u64, Option<Context>)>,
    // save_context: bool,
    dirty: BTreeSet<u64>,
    // seen: BTreeSet<u64>,
    breakpoints: BTreeSet<u64>,
    // status: EmulationStatus,
    // mem_access: Vec<(u64, u64, u64, usize, String)>,
    queue: Vec<(*mut std::ffi::c_void, u64, Option<Context>)>,
    // immediates: Vec<u64>,
    params: Option<Params>,
    trace: Option<Trace>,
    allocator: mem::Allocator,
    snapshot: &'a S,
}

impl <S: Snapshot> hook::Hooks for BochsHooks <'_, S> {
    // fn reset(&mut self, _id: u32, _ty: ResetSource) {}
    // fn hlt(&mut self, _id: u32) {}
    // fn mwait(&mut self, _id: u32, _addr: PhyAddress, _len: usize, _flags: u32) {}

    // fn cnear_branch_taken(&mut self, _id: u32, _branch_pc: bochscpu::Address, _new_pc: bochscpu::Address) {
    //     trace!("cnear branch taken {:x} {:x}", _branch_pc, _new_pc);
    // }

    // fn cnear_branch_not_taken(&mut self, _id: u32, _pc: bochscpu::Address, _new_pc: bochscpu::Address) {
    //     trace!("cnear branch not taken {:x} {:x}", _pc, _new_pc);
    // }

    // fn ucnear_branch(&mut self, _id: u32, _what: hook::Branch, _branch_pc: bochscpu::Address, _new_pc: bochscpu::Address) {
    //     trace!("uc near branch taken {:x} {:x}", _branch_pc, _new_pc);
    // }

    // fn far_branch( &mut self, _id: u32, _what: hook::Branch, _branch_pc: (u16, bochscpu::Address), _new_pc: (u16, bochscpu::Address),) {
    //     trace!("far branch taken {:?} {:x} {:x}", _what, _branch_pc.1, _new_pc.1);
    // }

    fn opcode( &mut self, _id: u32, ins: *const std::ffi::c_void, _opcode: &[u8], _is_32: bool, _is_64: bool,) {
        trace!("opcode {:x?}", _opcode);
        use bochscpu::opcode;
        let op = unsafe { opcode::instr_bx_opcode(ins) };

        const BX_IA_CMP_RAXID: u32 = 0x491;
        const BX_IA_CMP_EQSIB: u32 = 0x4a3;
        const BX_IA_CMP_EQID: u32 = 0x49a;
        const BX_IA_CMP_EAXID: u32 = 0x38;
        const BX_IA_CMP_EDID: u32 = 0x61;
        const BX_IA_CMP_EDSIB: u32 = 0x6a;
        const BX_IA_CMP_AXIW: u32 = 0x2f;
        const BX_IA_CMP_EWIW: u32 = 0x4f;
        const BX_IA_CMP_EWSIB: u32 = 0x58;

        if let Some(trace) = self.trace.as_mut() {

            match op {
                BX_IA_CMP_RAXID | BX_IA_CMP_EQID | BX_IA_CMP_EQSIB => {
                    let immediate = unsafe { opcode::instr_imm64(ins) };
                    trace.immediates.insert(immediate);
                }
                BX_IA_CMP_EAXID | BX_IA_CMP_EDID | BX_IA_CMP_EDSIB => {
                    let immediate = unsafe { opcode::instr_imm32(ins) };
                    trace.immediates.insert(immediate as u64);
                }
                BX_IA_CMP_AXIW | BX_IA_CMP_EWIW | BX_IA_CMP_EWSIB => {
                    let immediate = unsafe { opcode::instr_imm16(ins) };
                    trace.immediates.insert(immediate as u64);
                }
                _ => {
                    // println!("unknown opcode {:x}", op);
                }
            }
        }
    }

    // fn interrupt(&mut self, cpu_id: u32, vector: u32) {
    //     info!("interrupt {:?}", vector);
    // }
    // fn exception(&mut self, _id: u32, _vector: u32, _error_code: u32) {
    //     trace!("exception {:?}", _vector);
    // }
    // fn hw_interrupt(&mut self, _id: u32, _vector: u32, _pc: (u16, bochscpu::Address)) {
    //     trace!("hw interrupt {:?}", _vector);
    // }

    // fn tlb_cntrl(&mut self, _id: u32, _what: TlbCntrl, _new_cr: Option<PhyAddress>) {}
    // fn cache_cntrl(&mut self, _id: u32, _what: CacheCntrl) {}
    // fn prefetch_hint(&mut self, _id: u32, _what: PrefetchHint, _seg: u32, _off: Address) {}
    // fn clflush(&mut self, _id: u32, _vaddr: Address, _paddr: PhyAddress) {}

    fn before_execution(&mut self, cpu_id: u32, ins: *mut std::ffi::c_void) {
        // trace!("before {:?}", _ins);
        let cpu = Cpu::from(cpu_id);
        let rip = unsafe { cpu.rip() };

        if let (Some(trace), Some(params)) = (self.trace.as_mut(), self.params.as_ref()) {

            // sometime before execution is called twice, making traces completly false ...
            if params.save_context {
                let context: LocalContext = unsafe { cpu.state().into() };
                let context = context.0;
                self.queue.push((ins, rip, Some(context)));
            } else {
                self.queue.push((ins, rip, None));
            }

            if rip == params.return_address {
                trace!("found return address");
                trace.status = EmulationStatus::Success;
                unsafe { cpu.set_run_state(RunState::Stop) };
            }

            for (k, &v) in params.excluded_addresses.iter() {
                if v == rip {
                    let msg = format!("found excluded address {}", k);
                    trace.status = EmulationStatus::ForbiddenAddress(msg);
                    unsafe { cpu.set_run_state(RunState::Stop) };
                }
            }

            trace.seen.insert(rip);

            if !self.singlestep {
                for &v in self.breakpoints.iter() {
                    if v == rip {
                        trace.status = EmulationStatus::Breakpoint;
                        unsafe { cpu.set_run_state(RunState::Stop) };
                    }
                }
            }
        }
    }

    fn after_execution(&mut self, cpu_id: u32, ins: *mut std::ffi::c_void) {
        // trace!("after {:?}", _ins);

        if let (Some(trace), Some(params)) = (self.trace.as_mut(), self.params.as_ref()) {
            if let Some((a, b, c)) = self.queue.pop() {
                if a == ins {
                    trace.coverage.push((b, c));
                    self.instructions_count += 1;
                }
            }

            let cpu = Cpu::from(cpu_id);

            if self.singlestep {
                trace.status = EmulationStatus::SingleStep;
                unsafe { cpu.set_run_state(RunState::Stop) };
            }
            if params.limit != 0 && self.instructions_count > params.limit {
                warn!("limit exceeded");
                trace.status = EmulationStatus::LimitExceeded;
                unsafe { cpu.set_run_state(RunState::Stop) };
            }
        }
    }

    // fn repeat_iteration(&mut self, cpu_id: u32, ins: *mut std::ffi::c_void) {
    //     let cpu = Cpu::from(cpu_id);
    //     let rip = unsafe { cpu.rip() };
    //     if self.save_context {
    //         let context: LocalContext = unsafe { cpu.state().into() };
    //         let context = context.0;
    //         self.queue.push((ins, rip, Some(context)));
    //     } else {
    //         self.queue.push((ins, rip, None));
    //     }
    // }

    // fn inp(&mut self, _addr: u16, _len: usize) {}
    // fn inp2(&mut self, _addr: u16, _len: usize, _val: u32) {}
    // fn outp(&mut self, _addr: u16, _len: usize, _val: u32) {}

    fn lin_access(&mut self, cpu_id: u32, vaddr: bochscpu::Address, gpa: bochscpu::Address, len: usize, _memty: hook::MemType, rw: hook::MemAccess) {
        let cpu = Cpu::from(cpu_id);
        let rip = unsafe { cpu.rip() };

        // FIXME: push type
        // FIXME: need to push rip
        // FIXME: need to read value, lin access occurs after exec, so need to find read or written value...
        // FIXME: need to show proper rip too
        if let Some(trace) = self.trace.as_mut() {
            let access = format!("{:?}", rw);
            trace.mem_access.push((rip, vaddr, gpa, len, access));
            match rw {
                hook::MemAccess::Write | hook::MemAccess::RW => {
                    self.dirty.insert(gpa & !0xfff);
                },
                _ => (),
            }
        }
    }

    fn phy_access(&mut self, _cpu_id: u32, gpa: bochscpu::PhyAddress, _len: usize, _memty: hook::MemType, rw: hook::MemAccess) {
        match rw {
            hook::MemAccess::Write | hook::MemAccess::RW => {
                self.dirty.insert(gpa & !0xfff);
            },
            _ => (),
        }
    }

    fn wrmsr(&mut self, _cpu_id: u32, msr: u32, value: u64) {
        println!("writing to msr {:x} {:x}", msr, value);
    }

    // fn vmexit(&mut self, _id: u32, _reason: u32, _qualification: u64) {}

    fn missing_page(&mut self, paddr: bochscpu::Address) {
        let base = paddr & !0xfff;
        let pages: usize = self.allocator.allocate_physical_memory(0x1000);

        let slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(pages as *mut u8, 0x1000) };

        match self.snapshot.read_gpa(base, slice) {
            Ok(_) => {
                unsafe { guest_mem::page_insert(base, pages as *mut u8) };
            },
            _ => {
                println!("can't find page {:x} in dump", base);
                let cpu = Cpu::from(0);
                unsafe { cpu.set_run_state(RunState::Stop) };
            }
        };

    }
}

impl <'a, S: Snapshot> BochsHooks <'a, S> {

    fn new(snapshot: &'a S) -> Self {
        Self {
            singlestep: false,
            instructions_count: 0,
            dirty: BTreeSet::new(),
            breakpoints: BTreeSet::new(),
            queue: Vec::new(),
            params: None,
            trace: None,
            allocator: mem::Allocator::new(),
            snapshot,
        }
    }

}

/// Bochs based tracer        
pub struct BochsTracer <'a, S: Snapshot> {
    hooks: BochsHooks<'a, S>,
    breakpoints: BTreeSet<u64>,
    dirty: BTreeSet<u64>,

}

impl <'a, S: Snapshot> BochsTracer <'a, S> {

    /// Instanciate a tracer over a snapshot
    pub fn new(snapshot: &'a S) -> Self {

        unsafe { Cpu::new(0) };
        
        let hooks = BochsHooks::new(snapshot);

        Self {
            hooks,
            breakpoints: BTreeSet::new(),
            dirty: BTreeSet::new(),
        }

    }


}

impl <'a, S: Snapshot> Tracer for BochsTracer <'a, S> {

    fn get_state(&mut self) -> Result<ProcessorState, TracerError> {
        let c = Cpu::from(0);
        let mut state = ProcessorState::default();

        unsafe {
            state.rip = c.rip();
            state.rax = c.rax();
            state.rbx = c.rbx();
            state.rcx = c.rcx();
            state.rdx = c.rdx();
            state.rsi = c.rsi();
            state.rdi = c.rdi();
            state.rbp = c.rbp();
            state.rsp = c.rsp();
            state.rsp = c.rsp();
            state.r8 = c.r8();
            state.r9 = c.r9();
            state.r10 = c.r10();
            state.r11 = c.r11();
            state.r12 = c.r12();
            state.r13 = c.r13();
            state.r14 = c.r14();
            state.r15 = c.r15();
            state.rflags = c.rflags();

            state.gdtr = c.gdtr().base;
            state.gdtl = c.gdtr().limit;

            state.idtr = c.idtr().base;
            state.idtl = c.idtr().limit;

            state.cs.selector = c.cs().selector;
            state.cs.base = c.cs().base;
            state.cs.limit = c.cs().limit;

            state.ds.selector = c.ds().selector;
            state.ds.base = c.ds().base;
            state.ds.limit = c.ds().limit;

            state.es.selector = c.es().selector;
            state.es.base = c.es().base;
            state.es.limit = c.es().limit;

            state.fs.selector = c.fs().selector;
            state.fs.base = c.fs().base;
            state.fs.limit = c.fs().limit;

            state.gs.selector = c.gs().selector;
            state.gs.base = c.gs().base;
            state.gs.limit = c.gs().limit;

            state.ss.selector = c.ss().selector;
            state.ss.base = c.ss().base;
            state.ss.limit = c.ss().limit;
 
            state.cr0 = c.cr0() as u64;
            state.cr3 = c.cr3();
            state.cr4 = c.cr4() as u64;
            state.cr8 = c.cr8();

            state.kernel_gs_base = c.kernel_gs_base();
            state.efer = c.efer() as u64;
            state.star = c.star();
            state.lstar = c.lstar();
            state.cstar = c.cstar();

            state.apic_base = c.apic_base();

        }

        Ok(state)

    }

    fn set_state(&mut self, context: &ProcessorState) -> Result<(), TracerError> {
        let c = Cpu::from(0);

        let gdt = GlobalSeg {
            base: context.gdtr,
            limit: context.gdtl
        };

        let idt = GlobalSeg {
            base: context.idtr,
            limit: context.idtl
        };

        let cs = Seg {
            present: true,
            selector: context.cs.selector,
            base: context.cs.base,
            limit: context.cs.limit,
            attr: context.cs.flags,
        };

        let ss = Seg {
            present: true,
            selector: context.ss.selector,
            base: context.ss.base,
            limit: context.ss.limit,
            attr: context.ss.flags,
        };

        let ds = Seg {
            present: true,
            selector: context.ds.selector,
            base: context.ds.base,
            limit: context.ds.limit,
            attr: context.ds.flags,
        };

        let es = Seg {
            present: true,
            selector: context.es.selector,
            base: context.es.base,
            limit: context.es.limit,
            attr: context.es.flags,
        };

        let fs = Seg {
            present: true,
            selector: context.fs.selector,
            base: context.fs_base,
            limit: context.fs.limit,
            attr: context.fs.flags,
        };

        let gs = Seg {
            present: true,
            selector: context.gs.selector,
            base: context.gs_base,
            limit: context.gs.limit,
            attr: context.gs.flags,
        };

        unsafe {
            c.set_rip(context.rip);

            c.set_rax(context.rax);
            c.set_rbx(context.rbx);
            c.set_rcx(context.rcx);
            c.set_rdx(context.rdx);
            c.set_rsi(context.rsi);
            c.set_rdi(context.rdi);
            c.set_rsp(context.rsp);
            c.set_rbp(context.rbp);
            c.set_r8(context.r8);
            c.set_r9(context.r9);
            c.set_r10(context.r10);
            c.set_r11(context.r11);
            c.set_r12(context.r12);
            c.set_r13(context.r13);
            c.set_r14(context.r14);
            c.set_r15(context.r15);
            c.set_rflags(context.rflags);

            c.set_es(es);
            c.set_cs_raw(cs);
            c.set_ss(ss);
            c.set_ds(ds);
            c.set_fs(fs);
            c.set_gs(gs);
            
            c.set_gdtr(gdt);
            c.set_idtr(idt);

            c.set_cr0(context.cr0.try_into().map_err(|_| TracerError::UnknownError("bad cr0 value".into()))?);
            c.set_cr3(context.cr3);
            c.set_cr4(context.cr4.try_into().map_err(|_| TracerError::UnknownError("bad cr4 value".into()))?);
            c.set_cr8(context.cr8);
            // c.set_xcr0(0x1f);

            c.set_kernel_gs_base(context.kernel_gs_base);
            c.set_sysenter_cs(context.sysenter_cs);
            c.set_sysenter_esp(context.sysenter_esp);
            c.set_sysenter_eip(context.sysenter_eip);
            c.set_efer(context.efer.try_into().map_err(|_| TracerError::UnknownError("bad efer value".into()))?);
            c.set_star(context.star);
            c.set_lstar(context.lstar);
            c.set_cstar(context.cstar);

            c.set_apic_base(context.apic_base);

            c.set_mode();

            // trace!("{:#x?}", c.state());

        }

        Ok(())

    }

    fn run<H: trace::Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace, TracerError> {
        let c = Cpu::from(0);
        let start = Instant::now();

        self.hooks.trace = Some(Trace::new());

        // FIXME: need to work around lifetime issues
        self.hooks.params = Some(Params::default());
        if let Some(p) = self.hooks.params.as_mut() {
            p.return_address = params.return_address;
            p.save_context = params.save_context;
            p.max_duration = params.max_duration;
            p.coverage_mode = params.coverage_mode.clone();
            p.excluded_addresses = params.excluded_addresses.clone();
            p.limit = params.limit;
        }

        hook.setup(self);

        loop {

            self.hooks.breakpoints.extend(self.breakpoints.iter());
            unsafe { c.prepare().register(&mut self.hooks).run() };

            match self.hooks.trace.as_ref().unwrap().status {
                EmulationStatus::Breakpoint => {
                    hook.handle_breakpoint(self)?;
                    self.hooks.singlestep = true;

                },
                EmulationStatus::SingleStep => {
                    self.hooks.singlestep = false;
                },
                _ => {
                    break
                }
            }
        }   

        let mut trace = self.hooks.trace.take().unwrap();
        hook.handle_trace(&mut trace)?;

        let end = Instant::now();

        self.dirty.append(&mut self.hooks.dirty);
        trace.start = Some(start);
        trace.end = Some(end);
        Ok(trace)

    }

    fn restore_snapshot(&mut self) -> Result<usize, TracerError> {
        for page in &self.dirty {
            let buffer = unsafe { guest_mem::mem().get(page) };
            
            match buffer {
                Some(&buffer) => {
                    let slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, 0x1000) };
                    match self.hooks.snapshot.read_gpa(*page, slice) {
                        Ok(_) => {
                            trace!("restored page {:x}", page)
                        },
                        _ => {
                            warn!("can't find page in dump");
                        }
                    };
                },
                None => {
                    error!("dirty page not in guest mem, should not happen");

                }
            };

        }

        let pages = self.dirty.len();
        self.dirty.clear();
        Ok(pages)
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError> {
        // needed because hooks are removed when run is dropped 
        let c = Cpu::from(0);
        let _run = unsafe { c.prepare().register(&mut self.hooks) };
        guest_mem::virt_read_slice_checked(cr3, vaddr, data)
            .map_err(|e| TracerError::UnknownError(e.to_string()))?;
        Ok(())
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError> {
        let c = Cpu::from(0);
        let _run = unsafe { c.prepare().register(&mut self.hooks) };
        guest_mem::virt_write_checked(cr3, vaddr, data)
            .map_err(|e| TracerError::UnknownError(e.to_string())) ?;
        Ok(())
    }

    fn cr3(&mut self) -> Result<u64, TracerError> {
        let c = Cpu::from(0);
        Ok(unsafe { c.cr3() })
    }

    fn singlestep<H: trace::Hook>(&mut self, _params: &Params, _hook: &mut H) -> Result<Trace, TracerError> {
        let c = Cpu::from(0);
        // let start = Instant::now();

        let trace: Trace = Trace::new();
        self.hooks.singlestep = true;
        self.hooks.breakpoints.extend(self.breakpoints.iter());
 
        unsafe { c.prepare().run() };

        // trace!("executed {} instructions ({}) in {:?}", hooks.instructions_count, hooks.coverage.len(), start.elapsed());
        // trace!("seen {} unique addresses, dirty pages {}", hooks.seen.len(), hooks.dirty.len());

        Ok(trace)

    }

    fn add_breakpoint(&mut self, address: u64) {
        self.breakpoints.insert(address);

    }

    fn get_mapped_pages(&self) -> Result<usize, TracerError> {
        Ok(unsafe { guest_mem::mem().len() })
    }

}

impl <'a, S: Snapshot> mem::X64VirtualAddressSpace for BochsTracer <'a, S> {

    fn read_gpa(&self, address: u64, data: &mut[u8]) -> Result<(), VirtMemError> {
        guest_mem::phy_read_slice(address, data);
        Ok(())
    }

    fn write_gpa(&mut self, address: u64, data: &[u8]) -> Result<(), VirtMemError> {
        guest_mem::phy_write(address, data);
        Ok(())
    }

}

#[cfg(test)]
mod test {
    use mem::X64VirtualAddressSpace;

    use super::*;

    use std::io::Read;

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

    #[derive(Default)]
    struct TestSnapshot {

    }

    impl Snapshot for TestSnapshot {

        fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), rewind_core::snapshot::SnapshotError> {
            let base = gpa & !0xfff;
            let offset = (gpa & 0xfff) as usize;

            let mut data = vec![0u8; 0x1000];
            let path = std::path::PathBuf::from(format!("../tests/sdb/mem/{:016x}.bin", base));
            let mut fp = std::fs::File::open(path).unwrap();
            fp.read_exact(&mut data).unwrap();
            buffer.copy_from_slice(&data[offset..offset+buffer.len()]);
            Ok(())
        }

        fn get_cr3(&self) -> u64 {
            todo!()
        }

        fn get_module_list(&self) -> u64 {
            todo!()
        }
    }

    impl X64VirtualAddressSpace for TestSnapshot {

        fn read_gpa(&self, gpa: mem::Gpa, buf: &mut [u8]) -> Result<(), mem::VirtMemError> {
            Snapshot::read_gpa(self, gpa, buf).map_err(|_e| mem::VirtMemError::MissingPage(gpa))
        }

        fn write_gpa(&mut self, _gpa: mem::Gpa, _data: &[u8]) -> Result<(), mem::VirtMemError> {
            Ok(())
        }
    }

    #[test]
    fn test_tracer() {

        let path = std::path::PathBuf::from("../tests/sdb");
        let snapshot = TestSnapshot::default();

        let mut tracer = BochsTracer::new(&snapshot);
        let context = trace::ProcessorState::load(path.join("context.json")).unwrap();
        let mut params = trace::Params::default();
        let mut hook = TestHook::default();

        params.return_address = snapshot.read_gva_u64(context.cr3, context.rsp).unwrap();
        params.save_context = true;

        tracer.set_state(&context).unwrap();
        let trace = tracer.run(&params, &mut hook).unwrap();

        let expected = Trace::load(path.join("trace.json")).unwrap();

        for (index, (addr, context)) in expected.coverage.iter().enumerate() {
            assert_eq!(*addr, trace.coverage[index].0);
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
                assert_eq!(context.rip, expected_context.rip);
                assert_eq!(*addr, expected_context.rip);

            }

            assert_eq!(expected.seen.contains(addr), true);
            assert_eq!(trace.seen.contains(addr), true);

        }

        assert_eq!(trace.seen.len(), 2913);
        assert_eq!(trace.coverage.len(), 59120);
        assert_eq!(trace.immediates.len(), 22);
        assert_eq!(trace.mem_access.len(), 16650);

        assert_eq!(trace.status, trace::EmulationStatus::Success);

        assert_eq!(trace.coverage[0].0, context.rip);

        let state = tracer.get_state().unwrap();

        assert_eq!(state.rip, params.return_address);

        let pages = tracer.get_mapped_pages().unwrap();

        assert_eq!(pages, 80);

    }


}