
use std::convert::TryInto;
use std::collections::HashMap;
use std::collections::BTreeSet;
use std::time::Instant;

use anyhow::Result;

use rewind_core::mem;
use rewind_core::trace::{ProcessorState as InitialContext, Context, Params, Tracer, Trace, EmulationStatus};
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

#[derive(CustomDebug)]
struct BochsHooks {
    singlestep: bool,
    return_address: u64,
    excluded_addresses: HashMap<String, u64>,
    instructions_count: u64,
    limit: u64,
    coverage: Vec<(u64, Option<Context>)>,
    save_context: bool,
    dirty: BTreeSet<u64>,
    seen: BTreeSet<u64>,
    breakpoints: BTreeSet<u64>,
    status: EmulationStatus,
    mem_access: Vec<(u64, u64, usize, String)>,
    queue: Vec<(*mut std::ffi::c_void, u64, Option<Context>)>
}

impl hook::Hooks for BochsHooks {
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

    // fn opcode( &mut self, _id: u32, _ins: *const std::ffi::c_void, _opcode: &[u8], _is_32: bool, _is_64: bool,) {
    //     trace!("opcode {:x?}", _opcode);
    // }

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
        self.seen.insert(rip);

        // sometime before execution is called twice, making traces completly false ...
        if self.save_context {
            let context: LocalContext = unsafe { cpu.state().into() };
            let context = context.0;
            self.queue.push((ins, rip, Some(context)));
        } else {
            self.queue.push((ins, rip, None));
        }

        if rip == self.return_address {
            trace!("found return address");
            unsafe { cpu.set_run_state(RunState::Stop) };
        }

        if !self.singlestep {
            for &v in self.breakpoints.iter() {
                if v == rip {
                    self.status = EmulationStatus::Breakpoint;
                    unsafe { cpu.set_run_state(RunState::Stop) };
                }
            }
        }

        for (k, &v) in self.excluded_addresses.iter() {
            if v == rip {
                info!("found excluded address {}", k);
                self.status = EmulationStatus::ForbiddenAddress;
                unsafe { cpu.set_run_state(RunState::Stop) };
            }
        }

    }

    fn after_execution(&mut self, cpu_id: u32, ins: *mut std::ffi::c_void) {
        // trace!("after {:?}", _ins);

        if let Some((a, b, c)) = self.queue.pop() {
            if a == ins {
                self.coverage.push((b, c));
                self.instructions_count += 1;
            }
        }

        let cpu = Cpu::from(cpu_id);

        if self.singlestep {
            self.status = EmulationStatus::SingleStep;
            unsafe { cpu.set_run_state(RunState::Stop) };
        }
        if self.limit != 0 && self.instructions_count > self.limit {
            warn!("limit exceeded");
            self.status = EmulationStatus::LimitExceeded;
            unsafe { cpu.set_run_state(RunState::Stop) };
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

    fn lin_access(&mut self, _cpu_id: u32, vaddr: bochscpu::Address, gpa: bochscpu::Address, len: usize, _memty: hook::MemType, rw: hook::MemAccess) {
        // let cpu = Cpu::from(cpu_id);
        // let cr3 = unsafe { cpu.cr3() };

        // FIXME: push type
        // FIXME: need to push rip
        let access = String::from("TODO");
        self.mem_access.push((vaddr, gpa, len, access));
        match rw {
            hook::MemAccess::Write | hook::MemAccess::RW => {
                self.dirty.insert(gpa & !0xfff);
            },
            _ => (),
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

    // fn wrmsr(&mut self, _id: u32, _msr: u32, _val: u64) {}

    // fn vmexit(&mut self, _id: u32, _reason: u32, _qualification: u64) {}
}

impl BochsHooks {

    fn new(return_address: u64, limit: u64) -> Self {
        Self {
            singlestep: false,
            excluded_addresses: HashMap::new(),
            return_address: return_address,
            instructions_count: 0,
            limit: limit,
            coverage: Vec::new(),
            dirty: BTreeSet::new(),
            seen: BTreeSet::new(),
            breakpoints: BTreeSet::new(),
            save_context: false,
            status: EmulationStatus::Success,
            mem_access: Vec::new(),
            queue: Vec::new()
        }
    }

}

pub struct BochsTracer <S: 'static + Snapshot> {
    snapshot: &'static S,
    breakpoints: BTreeSet<u64>,
    dirty: BTreeSet<u64>

}

impl <S: 'static + Snapshot> BochsTracer <S> {

    pub fn new(snapshot: S) -> Result<Self> {

        unsafe { Cpu::new(0) };

        let static_ref: &'static S = Box::leak(Box::new(snapshot));
        let tracer = BochsTracer {
            snapshot: static_ref,
            breakpoints: BTreeSet::new(),
            dirty: BTreeSet::new(),
        };

        let mut allocator = mem::Allocator::new();

        unsafe {

            guest_mem::missing_page( move |paddr| {
                let base = paddr & !0xfff;
                let pages: usize = allocator.allocate_physical_memory(0x1000);

                let slice: &mut [u8] = std::slice::from_raw_parts_mut(pages as *mut u8, 0x1000);

                match static_ref.read_gpa(base, slice) {
                    Ok(_) => {
                        guest_mem::page_insert(base, pages as *mut u8);
                    },
                    _ => {
                        warn!("can't find page in dump");
                        let cpu = Cpu::from(0);
                        cpu.set_run_state(RunState::Stop);
                    }
                };
            });
        }

        Ok(tracer)
    }

    pub fn read_gpa(&self, address: u64, data: &mut[u8]) -> Result<()> {
        guest_mem::phy_read_slice(address, data);

        Ok(())

    }

    pub fn get_state(&self) -> Result<InitialContext> {
        let c = Cpu::from(0);
        let mut state = InitialContext::default();

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

        }

        Ok(state)

    }

    pub fn singlestep(&mut self, params: &Params) -> Result<Trace> {

        let c = Cpu::from(0);
        let start = Instant::now();

        let mut hooks: BochsHooks = params.into();
        hooks.singlestep = true;
        hooks.breakpoints.extend(&self.breakpoints);
 
        unsafe { c.prepare().register(&mut hooks).run() };

        trace!("executed {} instructions ({}) in {:?}", hooks.instructions_count, hooks.coverage.len(), start.elapsed());
        trace!("seen {} unique addresses, dirty pages {}", hooks.seen.len(), hooks.dirty.len());

        let trace: Trace = hooks.into();

        Ok(trace)

    }

    pub fn add_breakpoint(&mut self, address: u64) -> () {
        self.breakpoints.insert(address);

    }


}

impl From<BochsHooks> for Trace {

    fn from(hooks: BochsHooks) -> Self {
        let mut trace = Trace::new();
        trace.coverage = hooks.coverage;
        trace.status = hooks.status;
        trace.mem_access = hooks.mem_access;
        trace.seen = hooks.seen;
        trace
    }

}


impl From<&Params> for BochsHooks {

    fn from(params: &Params) -> Self {
        let mut hooks = BochsHooks::new(params.return_address, params.limit);
        hooks.save_context = params.save_context;
        hooks.excluded_addresses = params.excluded_addresses.clone();
        hooks
    }

}


impl <S: Snapshot> Tracer for BochsTracer <S> {

    fn set_initial_context(&mut self, context: &InitialContext) -> Result<()> {
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

            c.set_cr0(context.cr0.try_into()?);
            c.set_cr3(context.cr3);
            c.set_cr4(context.cr4.try_into()?);
            c.set_cr8(context.cr8);
            // c.set_xcr0(0x1f);

            c.set_kernel_gs_base(context.kernel_gs_base);
            c.set_sysenter_cs(context.sysenter_cs);
            c.set_sysenter_esp(context.sysenter_esp);
            c.set_sysenter_eip(context.sysenter_eip);
            c.set_efer(context.efer.try_into()?);
            c.set_star(context.star);
            c.set_lstar(context.lstar);
            c.set_cstar(context.cstar);

            c.set_mode();

            // trace!("{:#x?}", c.state());

        }

        Ok(())

    }

    fn run(&mut self, params: &Params) -> Result<Trace> {

        let c = Cpu::from(0);
        let start = Instant::now();

        // ctrlc::set_handler(move || {
        //     warn!("killed by ctrl-c");
        //     let cpu = Cpu::from(0);
        //     unsafe { cpu.set_run_state(RunState::Stop) };
        // }).expect("Error setting Ctrl-C handler");

        let mut hooks: BochsHooks = params.into();
        hooks.breakpoints.extend(&self.breakpoints);

        unsafe { c.prepare().register(&mut hooks).run() };

        let end = Instant::now();
        trace!("executed {} instructions ({}) in {:?}", hooks.instructions_count, hooks.coverage.len(), start.elapsed());
        trace!("seen {} unique addresses, dirty pages {}", hooks.seen.len(), hooks.dirty.len());

        self.dirty.append(&mut hooks.dirty);
        let mut trace: Trace = hooks.into();
        trace.start = Some(start);
        trace.end = Some(end);

        // FIXME: boarf to improve ...
        trace.code = unsafe { guest_mem::mem().len() };

        Ok(trace)

    }

    fn restore_snapshot(&mut self) -> Result<usize> {
        for page in &self.dirty {
            let buffer = unsafe { guest_mem::mem().get(page) };
            
            match buffer {
                Some(&buffer) => {
                    let slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, 0x1000) };
                    match self.snapshot.read_gpa(*page, slice) {
                        Ok(_) => {
                            trace!("restored page {:x}", page)
                        },
                        _ => {
                            warn!("can't find page in dump");
                        }
                    };
                },
                None => {

                }
            };

        }

        let pages = self.dirty.len();
        self.dirty.clear();
        Ok(pages)
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<()> {
        guest_mem::virt_read_slice_checked(cr3, vaddr, data)?;
        Ok(())
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()> {
        guest_mem::virt_write_checked(cr3, vaddr, data)?;
        Ok(())
    }

    fn cr3(&mut self) -> Result<u64> {
        let c = Cpu::from(0);
        Ok(unsafe { c.cr3() })
    }

}

