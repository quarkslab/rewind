
use std::convert::TryInto;
use std::collections::BTreeSet;
use std::time::Instant;

use anyhow::Result;

use rewind_core::mem;
use rewind_core::trace::{self, ProcessorState, Context, Params, Tracer, Trace, EmulationStatus};
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
#[derive(CustomDebug)]
struct BochsHooks<'a> {
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
    params: &'a Params,
    trace: &'a mut Trace,
}

impl <'a> hook::Hooks for BochsHooks <'a>{
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

        match op {
            BX_IA_CMP_RAXID | BX_IA_CMP_EQID | BX_IA_CMP_EQSIB => {
                let immediate = unsafe { opcode::instr_imm64(ins) };
                self.trace.immediates.insert(immediate);
            }
            BX_IA_CMP_EAXID | BX_IA_CMP_EDID | BX_IA_CMP_EDSIB => {
                let immediate = unsafe { opcode::instr_imm32(ins) };
                self.trace.immediates.insert(immediate as u64);
            }
            BX_IA_CMP_AXIW | BX_IA_CMP_EWIW | BX_IA_CMP_EWSIB => {
                let immediate = unsafe { opcode::instr_imm16(ins) };
                self.trace.immediates.insert(immediate as u64);
            }
            _ => {
                // println!("unknown opcode {:x}", op);
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

        // sometime before execution is called twice, making traces completly false ...
        if self.params.save_context {
            let context: LocalContext = unsafe { cpu.state().into() };
            let context = context.0;
            self.queue.push((ins, rip, Some(context)));
        } else {
            self.queue.push((ins, rip, None));
        }

        if rip == self.params.return_address {
            trace!("found return address");
            self.trace.status = EmulationStatus::Success;
            unsafe { cpu.set_run_state(RunState::Stop) };
        }

        for (k, &v) in self.params.excluded_addresses.iter() {
            if v == rip {
                let msg = format!("found excluded address {}", k);
                self.trace.status = EmulationStatus::ForbiddenAddress(msg);
                unsafe { cpu.set_run_state(RunState::Stop) };
            }
        }

        self.trace.seen.insert(rip);
        // if rip == 0xfffff8024b48fe2f {
        //     println!("skipping CfgReg_SaveRoot");
        //     unsafe {
        //         cpu.set_rax(0);
        //         cpu.set_rip(rip + 5);
        //     }
        // }

        // if rip == 0xfffff8024b48fe46 {
        //     println!("skipping CfgReg_Refresh");
        //     unsafe {
        //         cpu.set_rip(rip + 5);
        //     }
        // }

        if !self.singlestep {
            for &v in self.breakpoints.iter() {
                if v == rip {
                    self.trace.status = EmulationStatus::Breakpoint;
                    unsafe { cpu.set_run_state(RunState::Stop) };
                }
            }
        }
    }

    fn after_execution(&mut self, cpu_id: u32, ins: *mut std::ffi::c_void) {
        // trace!("after {:?}", _ins);

        if let Some((a, b, c)) = self.queue.pop() {
            if a == ins {
                self.trace.coverage.push((b, c));
                self.instructions_count += 1;
            }
        }

        let cpu = Cpu::from(cpu_id);

        if self.singlestep {
            self.trace.status = EmulationStatus::SingleStep;
            unsafe { cpu.set_run_state(RunState::Stop) };
        }
        if self.params.limit != 0 && self.instructions_count > self.params.limit {
            warn!("limit exceeded");
            self.trace.status = EmulationStatus::LimitExceeded;
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

    fn lin_access(&mut self, cpu_id: u32, vaddr: bochscpu::Address, gpa: bochscpu::Address, len: usize, _memty: hook::MemType, rw: hook::MemAccess) {
        let cpu = Cpu::from(cpu_id);
        let rip = unsafe { cpu.rip() };

        // FIXME: push type
        // FIXME: need to push rip
        let access = format!("{:?}", rw);
        self.trace.mem_access.push((rip, vaddr, gpa, len, access));
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

impl <'a> BochsHooks <'a> {

    fn new(params: &'a Params, trace: &'a mut Trace) -> Self {
        Self {
            singlestep: false,
            // excluded_addresses: HashMap::new(),
            // return_address: return_address,
            instructions_count: 0,
            // limit: limit,
            // coverage: Vec::new(),
            dirty: BTreeSet::new(),
            // seen: BTreeSet::new(),
            breakpoints: BTreeSet::new(),
            // save_context: false,
            // status: EmulationStatus::Success,
            queue: Vec::new(),
            params,
            trace,
        }
    }

}


pub struct BochsTracer <S: 'static + Snapshot> {
    pub snapshot: &'static S,
    pub breakpoints: BTreeSet<u64>,
    dirty: BTreeSet<u64>,

}

impl <S: 'static + Snapshot> BochsTracer <S> {

    pub fn new(snapshot: S) -> Result<Self> {

        unsafe { Cpu::new(0) };

        // FIXME: use drop to remove leak
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



}

impl <S: Snapshot> Tracer for BochsTracer <S> {

    fn get_state(&mut self) -> Result<ProcessorState> {
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

        }

        Ok(state)

    }

    fn set_state(&mut self, context: &ProcessorState) -> Result<()> {
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

    fn run<H: trace::Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace> {

        let c = Cpu::from(0);
        let start = Instant::now();

        let mut trace = Trace::new();
        let mut hooks = BochsHooks::new(params, &mut trace);

        let run = unsafe { c.prepare().register(&mut hooks) };
        hook.setup(self);

        loop {

            hooks.breakpoints.extend(self.breakpoints.iter());
            unsafe { run.run() };
            match hooks.trace.status {
                EmulationStatus::Breakpoint => {
                    hook.handle_breakpoint(self)?;
                    hooks.singlestep = true;

                },
                EmulationStatus::SingleStep => {
                    hooks.singlestep = false;
                },
                _ => {
                    break
                }
            }
        }   

        hook.handle_trace(hooks.trace)?;

        let end = Instant::now();

        self.dirty.append(&mut hooks.dirty);
        trace.start = Some(start);
        trace.end = Some(end);

        // FIXME: false, need a way to have only new pages, boarf to improve ...
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
                    error!("dirty page not in guest mem, should not happen");

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

    fn singlestep<H: trace::Hook>(&mut self, params: &Params, _hook: &mut H) -> Result<Trace> {
        let c = Cpu::from(0);
        // let start = Instant::now();

        let mut trace: Trace = Trace::new();
        let mut hooks = BochsHooks::new(params, &mut trace);
        hooks.singlestep = true;
        hooks.breakpoints.extend(self.breakpoints.iter());
 
        unsafe { c.prepare().register(&mut hooks).run() };

        // trace!("executed {} instructions ({}) in {:?}", hooks.instructions_count, hooks.coverage.len(), start.elapsed());
        // trace!("seen {} unique addresses, dirty pages {}", hooks.seen.len(), hooks.dirty.len());

        Ok(trace)

    }

    fn add_breakpoint(&mut self, address: u64) {
        self.breakpoints.insert(address);

    }

}

impl <S: Snapshot> mem::X64VirtualAddressSpace for BochsTracer <S> {

    fn read_gpa(&self, address: u64, data: &mut[u8]) -> Result<()> {
        guest_mem::phy_read_slice(address, data);
        Ok(())
    }

    fn write_gpa(&mut self, address: u64, data: &[u8]) -> Result<()> {
        guest_mem::phy_write(address, data);
        Ok(())
    }

}
