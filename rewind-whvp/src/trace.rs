
use std::{collections::BTreeSet, time::{Duration, Instant}};
use std::convert::TryInto;

use anyhow::Result;

use rewind_core::mem::{self, X64VirtualAddressSpace};
use rewind_core::trace::{self, ProcessorState, Context, Params, Tracer, Trace, EmulationStatus, CoverageMode};
use rewind_core::snapshot::Snapshot;

use crate::whvp;

impl From<whvp::PartitionContext> for Context {

    fn from(context: whvp::PartitionContext) -> Self {
        Context {
            rax: unsafe { context.rax.Reg64 },
            rbx: unsafe { context.rbx.Reg64 },
            rcx: unsafe { context.rcx.Reg64 },
            rdx: unsafe { context.rdx.Reg64 },
            rsi: unsafe { context.rsi.Reg64 },
            rdi: unsafe { context.rdi.Reg64 },
            rsp: unsafe { context.rsp.Reg64 },
            rbp: unsafe { context.rbp.Reg64 },
            r8: unsafe { context.r8.Reg64 },
            r9: unsafe { context.r9.Reg64 },
            r10: unsafe { context.r10.Reg64 },
            r11: unsafe { context.r11.Reg64 },
            r12: unsafe { context.r12.Reg64 },
            r13: unsafe { context.r13.Reg64 },
            r14: unsafe { context.r14.Reg64 },
            r15: unsafe { context.r15.Reg64 },
            rflags: unsafe { context.rflags.Reg64 },
            rip: unsafe { context.rip.Reg64 },
        }
    }
}

pub struct WhvpTracer <S: Snapshot> {
    cache: mem::GpaManager,
    allocator: mem::Allocator,
    partition: whvp::Partition,
    breakpoints: BTreeSet<u64>,
    snapshot: S,
}

impl <S: Snapshot + mem::X64VirtualAddressSpace> WhvpTracer <S>{

    pub fn new(snapshot: S) -> Result<Self> {
        let allocator = mem::Allocator::new();
        let cache = mem::GpaManager::new();
        let partition = whvp::Partition::new()?;

        let tracer = WhvpTracer {
            cache,
            allocator,
            partition,
            breakpoints: BTreeSet::new(),
            snapshot,
        };

        Ok(tracer)
    }

    pub fn map_page(&mut self, gpa: u64, data: &[u8]) -> Result<()> {
        let partition = &mut self.partition;
        let allocator = &mut self.allocator;
        let base: usize = (gpa & !0xfff).try_into()?;
        let pages: usize = allocator.allocate_physical_memory(0x1000);

        let permissions = whvp::MapGpaRangeFlags::Read
                    | whvp::MapGpaRangeFlags::Write
                    | whvp::MapGpaRangeFlags::Execute;

        partition.map_physical_memory(base, pages, 0x1000, permissions.bits())?;
        partition.write_physical_memory(base, data)?;

       
        Ok(())
    }

    pub fn fetch_page_from_snapshot(&mut self, gpa: u64, data: &mut [u8]) -> Result<()> {
        let snapshot = &self.snapshot;
        let base: usize = (gpa & !0xfff).try_into()?;
        Snapshot::read_gpa(snapshot, base as u64, data)?;
        Ok(())

    }

    pub fn patch_page(&mut self, params: &Params, access_type: whvp::MemoryAccessType, gva: u64, data: &mut [u8]) -> Result<()> {
        if params.coverage_mode == CoverageMode::Hit && access_type == whvp::MemoryAccessType::Execute {
            // FIXME: add this to parameter
            let gva_base = 0xfffff80480689000;
            if gva_base <= gva && gva < gva_base + 0x1000 {
                println!("ignoring gva range {:x}", gva_base);

            } else {
                data.copy_from_slice(&[0xcc; 4096]);
            }
        } 
        else {
            let gva_base = params.return_address & !0xfff;
            let offset: usize = (params.return_address & 0xfff).try_into()?;
            if gva_base <= gva && gva < gva_base + 0x1000 {
                trace!("setting bp on return address {:x}", params.return_address);
                data[offset] = 0xcc;
            }

            for (name, &addr) in params.excluded_addresses.iter() {
                let gva_base = addr & !0xfff;
                let offset: usize = (addr & 0xfff).try_into()?;
                if gva_base <= gva && gva < gva_base + 0x1000 {
                    println!("setting bp on excluded address {} ({:x})", name, addr);
                    data[offset] = 0xcc;
                }
            }

            for &addr in self.breakpoints.iter() {
                let gva_base = addr & !0xfff;
                let offset: usize = (addr & 0xfff).try_into()?;
                if gva_base <= gva && gva < gva_base + 0x1000 {
                    println!("setting bp on breakpoint {:x}", addr);
                    data[offset] = 0xcc;
                }
            }
        }
        Ok(())
 
    }

    fn handle_memory_access_inner(&mut self, params: &Params, gpa: u64, gva: u64, access_type: whvp::MemoryAccessType, trace: &mut Trace) -> Result<bool> {
        match access_type {
            whvp::MemoryAccessType::Execute => {
                trace.code += 1;
            },
            _ => {
                trace.data += 1;
            }
        }

        let mut data: [u8; 4096] = [0; 4096];
        self.fetch_page_from_snapshot(gpa, &mut data)?;

        let base: usize = (gpa & !0xfff).try_into()?;
        let cache = &mut self.cache;
        cache.add_page(base as u64, data);
 
        self.patch_page(params, access_type, gva, &mut data)?;
        self.map_page(gpa, &data)?;

        Ok(true)
    }

    fn handle_memory_access(&mut self, params: &Params, memory_access_context: &whvp::MemoryAccessContext, trace: &mut Trace) -> Result<bool> {
        let gpa = memory_access_context.Gpa;
        let gva = memory_access_context.Gva;
        let access_type = memory_access_context.AccessInfo.AccessType;
        self.handle_memory_access_inner(params, gpa, gva, access_type, trace)?;

        Ok(true)
    }

    fn handle_exception(&mut self, params: &Params, vp_context: &whvp::VpContext, exception_context: &whvp::ExceptionContext, trace: &mut Trace) -> Result<bool> {
        let partition = &mut self.partition;

        if vp_context.ExecutionState.InterruptShadow {
            let mut interrupt_context = partition.get_regs()?;
            unsafe {
                interrupt_context
                    .interrupt_state
                    .InterruptState
                    .__bindgen_anon_1
                    .set_InterruptShadow(0)
            };
            partition.set_regs(&interrupt_context)?;
        }

        let rip = vp_context.Rip;

        if rip as u64 == params.return_address {
            return Ok(false);
        }

        for (k, &v) in params.excluded_addresses.iter() {
            if v == rip {
                trace.status = EmulationStatus::ForbiddenAddress(k.to_string());
                return Ok(false);
            }
        }

        let exception_type: whvp::ExceptionType = exception_context.ExceptionType.into();
        match exception_type {
            whvp::ExceptionType::DebugTrapOrFault | whvp::ExceptionType::BreakpointTrap => {
                trace.seen.insert(rip);
                if params.save_context {
                    let context = partition.get_regs()?.into();
                    trace.coverage.push((rip, Some(context)));
                } else {
                    trace.coverage.push((rip, None));
                }
            },
            _ => {
                trace.status = EmulationStatus::UnHandledException;
                return Ok(false)
            }
        }

        let mut regs = self.partition.get_regs()?;
        let rflags = unsafe { regs.rflags.Reg64 };
        if params.coverage_mode != CoverageMode::Instrs && rflags & 0x100 == 0x100 {
            trace.status = EmulationStatus::SingleStep;
        }

        if params.coverage_mode != CoverageMode::Instrs && exception_type == whvp::ExceptionType::DebugTrapOrFault {
            regs.rflags.Reg64 = rflags & !0x100;
            self.partition.set_regs(&regs)?;
        }

        if exception_type == whvp::ExceptionType::BreakpointTrap {
            let offset = (rip & 0xfff) as usize;
            let remain = (0x1000 - offset) as usize;

            let size = 0x10;
            let mut buffer = vec![0u8; size];
            let cr3 = self.cr3()?;
            match self.snapshot.read_gva(cr3, rip as u64, &mut buffer) {
                Ok(()) => {},
                _ => {
                    let msg = format!("can't read instruction at rip {:x}", rip);
                    trace.status = EmulationStatus::Error(msg);
                    return Err(anyhow!("can't read instruction at rip {:x}", rip))
                }
            }

            match self.decode_instruction(&buffer) {
                Ok(instruction) => {
                    let length = instruction.length as usize;
                    if length > remain {
                        let base = (rip + length as u64) & !0xfff;
                        let paddr = self.snapshot.translate_gva(cr3, base)?;
                        if self.cache.pages.get(&paddr).is_none() { 
                            // println!("need to map {:x} {:x}, rip {:x}", base, paddr, rip);
                            self.handle_memory_access_inner(params, paddr, base, whvp::MemoryAccessType::Execute, trace)?;
                        }
                    }

                    self.write_gva(cr3, rip, &buffer[..length])?;
                }, 
                _ => {
                    let msg = format!("can't decode instruction for {:x}", rip);
                    trace.status = EmulationStatus::Error(msg);
                    return Err(anyhow!("can't decode instruction at rip {:x}", rip))
                }
            }

        }

        if trace.status == EmulationStatus::SingleStep {
            Ok(false)
        } else {
            for &addr in self.breakpoints.iter() {
                if addr == rip {
                    trace.status = EmulationStatus::Breakpoint;
                    return Ok(false);
                }
            }
            Ok(true)
        }

    }

    fn decode_instruction(&mut self, buffer: &[u8]) -> Result<zydis::DecodedInstruction> {
        let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?;
        let result = decoder.decode(&buffer)?;
        if let Some(instruction) = result {
            Ok(instruction)
        } else {
            Err(anyhow!("can't decode instruction"))
        }
    }

    // fn format_instruction(&mut self, rip: u64, instruction: zydis::DecodedInstruction) -> Result<String> {
    //     let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
    //     let mut buffer = [0u8; 200];
    //     let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
    //     formatter.format_instruction(&instruction, &mut buffer, Some(rip as u64), None)?;
    //     let output = format!("0x{:016X}: {}", rip, buffer);
    //     Ok(output)
    // }

}


impl <S: Snapshot + mem::X64VirtualAddressSpace> Tracer for WhvpTracer <S> {

    fn get_state(&mut self) -> Result<ProcessorState> {
        let mut state = ProcessorState::default();

        let partition = &mut self.partition;
        let regs = partition.get_regs()?;

        unsafe {
            state.rax = regs.rax.Reg64;
            state.rbx = regs.rbx.Reg64;
            state.rcx = regs.rcx.Reg64;
            state.rdx = regs.rdx.Reg64;
            state.rsi = regs.rsi.Reg64;
            state.rdi = regs.rdi.Reg64;
            state.rsp = regs.rsp.Reg64;
            state.rbp = regs.rbp.Reg64;
            state.r8 = regs.r8.Reg64;
            state.r9 = regs.r9.Reg64;
            state.r10 = regs.r10.Reg64;
            state.r11 = regs.r11.Reg64;
            state.r12 = regs.r12.Reg64;
            state.r13 = regs.r13.Reg64;
            state.r14 = regs.r14.Reg64;
            state.r15 = regs.r15.Reg64;
            state.rflags = regs.rflags.Reg64;
            state.rip = regs.rip.Reg64;
            state.cr0 = regs.cr0.Reg64;
            state.cr3 = regs.cr3.Reg64;
            state.cr4 = regs.cr4.Reg64;
            state.cr8 = regs.cr8.Reg64;
            state.efer = regs.efer.Reg64;
            state.star = regs.star.Reg64;
            state.lstar = regs.lstar.Reg64;
            state.cstar = regs.cstar.Reg64;
            state.apic_base = regs.apic_base.Reg64;
            state.kernel_gs_base = regs.kernel_gs_base.Reg64;
            state.gdtr = regs.gdtr.Table.Base;
            state.gdtl = regs.gdtr.Table.Limit;
            state.idtr = regs.idtr.Table.Base;
            state.idtl = regs.idtr.Table.Limit;

            state.cs.selector = regs.cs.Segment.Selector;
            state.ss.selector = regs.ss.Segment.Selector;
            state.ds.selector = regs.ds.Segment.Selector;
            state.es.selector = regs.es.Segment.Selector;
            state.fs.selector = regs.fs.Segment.Selector;
            state.gs.selector = regs.gs.Segment.Selector;

            state.gs_base = regs.gs.Segment.Base;
            state.fs_base = regs.fs.Segment.Base;
        }

        Ok(state)

    }

    fn set_state(&mut self, context: &ProcessorState) -> Result<()> {
        let partition = &mut self.partition;
        let mut regs = partition.get_regs()?;

        regs.rax.Reg64 = context.rax;
        regs.rbx.Reg64 = context.rbx;
        regs.rcx.Reg64 = context.rcx;
        regs.rdx.Reg64 = context.rdx;
        regs.rsi.Reg64 = context.rsi;
        regs.rdi.Reg64 = context.rdi;
        regs.rsp.Reg64 = context.rsp;
        regs.rbp.Reg64 = context.rbp;
        regs.r8.Reg64 = context.r8;
        regs.r9.Reg64 = context.r9;
        regs.r10.Reg64 = context.r10;
        regs.r11.Reg64 = context.r11;
        regs.r12.Reg64 = context.r12;
        regs.r13.Reg64 = context.r13;
        regs.r14.Reg64 = context.r14;
        regs.r15.Reg64 = context.r15;
        regs.rflags.Reg64 = context.rflags;
        regs.rip.Reg64 = context.rip;
        regs.cr0.Reg64 = context.cr0;
        regs.cr3.Reg64 = context.cr3;
        regs.cr4.Reg64 = context.cr4;
        regs.cr8.Reg64 = context.cr8;
        regs.efer.Reg64 = context.efer;

        regs.star.Reg64 = context.star;
        regs.lstar.Reg64 = context.lstar;
        regs.cstar.Reg64 = context.cstar;

        regs.apic_base.Reg64 = context.apic_base;

        regs.kernel_gs_base.Reg64 = context.kernel_gs_base;

        regs.gdtr.Table.Base = context.gdtr;
        regs.gdtr.Table.Limit = context.gdtl;

        regs.idtr.Table.Base = context.idtr;
        regs.idtr.Table.Limit = context.idtl;

        // FIXME: forward long mode and privilege level (read from attr?)
        regs.cs.Segment.Base = 0;
        regs.cs.Segment.Limit = 0;
        unsafe {
            regs.cs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(1);
            regs.cs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.cs.Segment.Selector = context.cs.selector;

        regs.ss.Segment.Base = 0;
        regs.ss.Segment.Limit = 0;
        unsafe {
            regs.ss
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.ss
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.ss.Segment.Selector = context.ss.selector;

        regs.ds.Segment.Base = 0;
        regs.ds.Segment.Limit = 0;
        unsafe {
            regs.ds
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.ds
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.ds.Segment.Selector = context.ds.selector;

        regs.es.Segment.Base = 0;
        regs.es.Segment.Limit = 0;
        unsafe {
            regs.es
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.es
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.es.Segment.Selector = context.es.selector;

        regs.fs.Segment.Base = context.fs_base;
        regs.fs.Segment.Limit = 0;
        unsafe {
            regs.fs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.fs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.fs.Segment.Selector = context.fs.selector;

        regs.gs.Segment.Base = context.gs_base;
        regs.gs.Segment.Limit = 0;
        unsafe {
            regs.gs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.gs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.gs.Segment.Selector = context.gs.selector;

        partition.set_regs(&regs)?;
        Ok(())
    }

    fn run<H: trace::Hook>(&mut self, params: &Params, _hook: &mut H) -> Result<Trace> {
        let mut exits = 0;
        let mut cancel = 0;

        let mut trace = Trace::new();

        let mut regs = self.partition.get_regs()?;
        let rip = unsafe { regs.rip.Reg64 };
        // let cr3 = unsafe { regs.cr3.Reg64 };
 
        // let breakpoints = self.breakpoints.clone();
        // let _writes: Vec<_> = breakpoints.iter().map(|&addr| {
        //     self.write_gva(cr3, addr, &[0xcc])
        // }).collect();

        if params.coverage_mode == CoverageMode::Instrs {
            let rflags = unsafe { regs.rflags.Reg64 };
            regs.rflags.Reg64 = rflags | 0x100;
            self.partition.set_regs(&regs)?;
        }

        if params.coverage_mode != CoverageMode::Hit {
            trace.seen.insert(rip);
            if params.save_context {
                let context = regs.into();
                trace.coverage.push((rip, Some(context)));
            } else {
                trace.coverage.push((rip, None));
            }
        }

        trace.start = Some(Instant::now());

        while params.limit == 0 || exits < params.limit {
            let exit = self.partition.run()?;
            exits += 1;
            if params.max_duration != Duration::default() && trace.start.unwrap().elapsed() > params.max_duration {
                trace.status = EmulationStatus::Timeout;
                break;
            }
            let exit_context: whvp::ExitContext = exit.into();
            match exit_context {
                whvp::ExitContext::MemoryAccess(_vp_context, memory_access_context) => {
                    cancel = 0;
                    match self.handle_memory_access(&params, &memory_access_context, &mut trace) {
                        Ok(_) => (),
                        Err(e) => {
                            let msg = format!("{}", e);
                            trace.status = EmulationStatus::Error(msg);
                            break;
                        }
                    }
                }
                whvp::ExitContext::Exception(vp_context, exception_context) => {
                    cancel = 0;
                    match self.handle_exception(&params, &vp_context, &exception_context, &mut trace) {
                        Ok(false) => {
                            break;
                        },
                        Ok(true) => (),
                        Err(e) => {
                            let msg = format!("{}", e);
                            trace.status = EmulationStatus::Error(msg);
                            break;
                        }
                    }
                }
                whvp::ExitContext::X64MsrAccess(vp_context, msr_access_context) => {
                    // FIXME: need a fn handle_msr_access
                    cancel = 0;
                    let rip = vp_context.Rip;
                    trace!("got msr access: rip {:x}, write {}, number {:x} rax {:x} rdx {:x}",
                        rip,
                        msr_access_context.AccessInfo.IsWrite,
                        msr_access_context.MsrNumber,
                        msr_access_context.Rax,
                        msr_access_context.Rdx);

                    let mut regs = self.partition.get_regs()?;
                    regs.rip.Reg64 = rip + 2;
                    self.partition.set_regs(&regs)?;

                    trace.seen.insert(rip);
                    if params.save_context {
                        let context = regs.into();
                        trace.coverage.push((rip, Some(context)));
                    } else {
                        trace.coverage.push((rip, None));
                    }
                }
                whvp::ExitContext::Canceled(_, _) => {
                    cancel += 1;
                    if cancel > 10 {
                        error!("stopping, seems stucked");
                        trace.status = EmulationStatus::Timeout;
                        break;
                    }
                }
                _ => {
                    let msg = format!("unhandled vm exit: {:?}", exit_context);
                    trace.status = EmulationStatus::Error(msg);
                    break;
                }
            }
        }
        trace.end = Some(Instant::now());
        Ok(trace)
    }

    fn restore_snapshot(&mut self) -> Result<usize> {
        // let start = Instant::now();
        let mut pages: usize = 0;
        let partition = &mut self.partition;
        let regions = &mut partition.mapped_regions;
        let addresses = regions.iter().map(|region| region.base).collect::<Vec<_>>();
        // FIXME: compute range ?
        // addresses.sort();
        for addr in addresses.iter() {
            let bitmap = partition.query_gpa_range(*addr, 0x1000)?;
            if bitmap == 1 {
                if let Some(arr) = self.cache.pages.get(&(*addr as u64)) {
                    match partition.write_physical_memory(*addr, arr) {
                        Ok(_) => {
                            partition.flush_gpa_range(*addr, 0x1000)?;
                            pages += 1;
                        }
                        _ => {
                            return Err(anyhow!("can't restore data"))
                        }
                    }
                }
            }
        }
        // info!("restored {} pages from snapshot in {:?}", pages, start.elapsed());
        Ok(pages)
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<()> {
        match self.partition.read_gva(cr3, vaddr, data) {
            Err(_) => {
                let pages = self.snapshot.translate_gva_range(cr3, vaddr, data.len())?;
                let mut mapped_pages = BTreeSet::new();
                for base in pages.iter() {
                    if self.cache.pages.get(base).is_none() {
                        mapped_pages.insert(*base);
                    } 
                }

                for base in mapped_pages.iter() {
                    let mut data = [0u8; 0x1000];
                    self.fetch_page_from_snapshot(*base, &mut data)?;
        
                    self.map_page(*base, &data)?;
                    self.cache.add_page(*base, data);

                }

                self.read_gva(cr3, vaddr, data)

            }
            a => a
        }
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()> {
        match self.partition.write_gva(cr3, vaddr, data) {
            Err(_) => {
                let pages = self.snapshot.translate_gva_range(cr3, vaddr, data.len())?;
                let mut mapped_pages = BTreeSet::new();
                for base in pages.iter() {
                    if self.cache.pages.get(base).is_none() {
                        mapped_pages.insert(*base);
                        
                    } 
                }
                for base in mapped_pages.iter() {
                    let mut data = [0u8; 0x1000];
                    self.fetch_page_from_snapshot(*base, &mut data)?;
        
                    self.map_page(*base, &data)?;
                    self.cache.add_page(*base, data);

                }
                self.write_gva(cr3, vaddr, data)

            }
            a => a
        }
    }

    fn cr3(&mut self) -> Result<u64> {
        let context = self.partition.get_regs()?;
        let cr3 = unsafe { context.cr3.Reg64 };
        Ok(cr3)
    }

    fn singlestep<H: trace::Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace> {
        let mut context = self.partition.get_regs()?;
        let cr3 = unsafe {context.cr3.Reg64 };
        let rflags = unsafe { context.rflags.Reg64 };
        context.rflags.Reg64 = rflags | 0x100;
        self.partition.set_regs(&context)?;

        // awful /o\
        // reactivate bp only if mem is mapped
        // need to check if bp is valid
        // FIXME: change prototype
        // should be in cli run
        let breakpoints = self.breakpoints.clone();
        let _writes: Vec<_> = breakpoints.iter().map(|&addr| {
            self.partition.read_gva_u8(cr3, addr).and_then(|_| {
                self.partition.write_gva(cr3, addr, &[0xcc])
            })
        }).collect();

        let trace = trace::Trace::new();
        // let trace = self.run(params, hook)?;

        Ok(trace)
    }

    fn add_breakpoint(&mut self, address: u64) {
        self.breakpoints.insert(address);

    }

}

 