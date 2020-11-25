
use std::time::{Duration, Instant};
use std::convert::TryInto;

use anyhow::{Result, Context as _};

use rewind_core::mem::{self, X64VirtualAddressSpace};
use rewind_core::trace::{ProcessorState, Context, Params, Tracer, Trace, EmulationStatus, CoverageMode};
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
    snapshot: S,
}

impl <S: Snapshot + mem::X64VirtualAddressSpace> WhvpTracer <S>{

    pub fn new(snapshot: S) -> Result<Self> {
        let allocator = mem::Allocator::new();
        let cache = mem::GpaManager::new();
        let partition = whvp::Partition::new()?;

        let tracer = WhvpTracer {
            cache: cache,
            allocator: allocator,
            partition: partition,
            snapshot: snapshot,
        };

        Ok(tracer)
    }

    fn map_page(&mut self, params: &Params, gva: u64, gpa: u64, access_type: whvp::MemoryAccessType) -> Result<bool> {
        let partition = &mut self.partition;
        let allocator = &mut self.allocator;
        
        let cache = &mut self.cache;
        let snapshot = &self.snapshot;

        let base: usize = (gpa & !0xfff).try_into()?;
        let mut data: [u8; 4096] = [0; 4096];

        match Snapshot::read_gpa(snapshot, base as u64, &mut data) {
            Ok(_) => {
                cache.add_page(base as u64, data);
            },
            Err(e) => {
                warn!("can't read gpa {:x} from snapshot ({})", gpa, e);
                return Ok(false);
            }
        }

        if params.coverage_mode == CoverageMode::Hit && access_type == whvp::MemoryAccessType::Execute {
            data.copy_from_slice(&[0xcc; 4096]);
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
                    trace!("setting bp on excluded address {} ({:x})", name, addr);
                    data[offset] = 0xcc;
                }
            }
        }

        let pages: usize = allocator.allocate_physical_memory(0x1000);
        let permissions = whvp::MapGpaRangeFlags::Read
                    | whvp::MapGpaRangeFlags::Write
                    | whvp::MapGpaRangeFlags::Execute;

        partition.map_physical_memory(base, pages, 0x1000, permissions.bits())?;
        partition.write_physical_memory(base, &data)?;
 
        Ok(true)
    }

    fn handle_memory_access(&mut self, params: &Params, memory_access_context: &whvp::MemoryAccessContext, trace: &mut Trace) -> Result<bool> {
        // let partition = &mut self.partition;
        // let allocator = &mut self.allocator;
        // let cache = &mut self.cache;
        // let snapshot = &self.snapshot;

        // let gpa = memory_access_context.Gpa;
        // let gva = memory_access_context.Gva;

        // let base: usize = (gpa & !0xfff).try_into()?;
        // let mut data: [u8; 4096] = [0; 4096];

        // match Snapshot::read_gpa(snapshot, base as u64, &mut data) {
        //     Ok(_) => {
        //         cache.add_page(base as u64, data);
        //     },
        //     Err(e) => {
        //         warn!("can't read gpa {:x} from snapshot ({})", gpa, e);
        //         trace.status = EmulationStatus::Error;
        //         return Ok(true);
        //     }
        // }
        
        // let access_type = memory_access_context.AccessInfo.AccessType;

        // match access_type {
        //     whvp::MemoryAccessType::Execute => {
        //         trace.code += 1;
        //     },
        //     _ => {
        //         trace.data += 1;
        //     }
        // }

        // if params.coverage_mode == CoverageMode::Hit && access_type == whvp::MemoryAccessType::Execute {
        //     data.copy_from_slice(&[0xcc; 4096]);
        // } 
        // else {
        //     let gva_base = params.return_address & !0xfff;
        //     let offset: usize = (params.return_address & 0xfff).try_into()?;
        //     if gva_base <= gva && gva < gva_base + 0x1000 {
        //         info!("setting bp on return address {:x}", params.return_address);
        //         data[offset] = 0xcc;
        //     }

        //     for (name, &addr) in params.excluded_addresses.iter() {
        //         let gva_base = addr & !0xfff;
        //         let offset: usize = (addr & 0xfff).try_into()?;
        //         if gva_base <= gva && gva < gva_base + 0x1000 {
        //             info!("setting bp on excluded address {} ({:x})", name, addr);
        //             data[offset] = 0xcc;
        //         }
        //     }
        // }

        // let pages: usize = allocator.allocate_physical_memory(0x1000);
        // let permissions = whvp::MapGpaRangeFlags::Read
        //             | whvp::MapGpaRangeFlags::Write
        //             | whvp::MapGpaRangeFlags::Execute;

        // partition.map_physical_memory(base, pages, 0x1000, permissions.bits())?;
        // partition.write_physical_memory(base, &data)?;
        // Ok(false)
        let gpa = memory_access_context.Gpa;
        let gva = memory_access_context.Gva;
        let access_type = memory_access_context.AccessInfo.AccessType;

        match access_type {
            whvp::MemoryAccessType::Execute => {
                trace.code += 1;
            },
            _ => {
                trace.data += 1;
            }
        }

        let result = match self.map_page(params, gva, gpa, access_type) {
            Ok(true) => {
                Ok(true)
            },
            Ok(false) => {
                trace.status = EmulationStatus::Error;
                Ok(false)
            },
            Err(e) => {
                Err(e)
            }
        };

        let gva_valid = memory_access_context.AccessInfo.GvaValid;
        if params.coverage_mode == CoverageMode::Hit && access_type == whvp::MemoryAccessType::Execute && gva_valid {
            // try to map next page

            let cr3 = self.cr3()?;
            let cache = &mut self.cache;

            let pages = &cache.pages;
            let mut to_map = vec![];
            let next_gva = (gva + 0x1000) & !0xfff;
            // FIXME: false, gva sent to map_page is incorrect
            match cache.translate_gva_range(cr3, next_gva) {
                Ok((base, size)) => {
                    let start = base;
                    let end = base + size as u64;
                    for gpa in (start..=end).step_by(0x1000) {
                        if pages.get(&gpa).is_none() { 
                            to_map.push(gpa);
                        }
                    }
                }
                Err(err) => {
                    info!("can't translate gva {:?}", err);
                }
            }
            // info!("need to map {} pages", to_map.len());
            for gpa in &to_map {
                match self.map_page(params, gva, *gpa, whvp::MemoryAccessType::Execute) {
                    Ok(_) => {
                        trace.code += 1;
                    }
                    _ => ()
                }
            }
        }

        result

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
            trace!("got return address");
            return Ok(false);
        }

        for (_k, &v) in params.excluded_addresses.iter() {
            if v == rip {
                trace.status = EmulationStatus::ForbiddenAddress;
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

        if params.coverage_mode == CoverageMode::Hit && exception_type == whvp::ExceptionType::BreakpointTrap {
            // let offset = (rip & 0xfff) as usize;
            // let remain = (0x1000 - offset) as usize;

            // let size = std::cmp::min(0x10, remain);
            let size = 0x10;
            let mut buffer = vec![0u8; size];
            let cr3 = self.cr3()?;
            match self.cache.read_gva(cr3, rip as u64, &mut buffer) {
                Ok(()) => {},
                _ => {
                    warn!("can't read cache for {:x}", rip);
                    trace.status = EmulationStatus::Error;
                    return Ok(false)
                }
            }

            match self.decode_instruction(&buffer) {
                Ok(instruction) => {
                    let length = instruction.length as usize;
                    self.write_gva(cr3, rip, &buffer[..length])?;
                }, 
                _ => {
                    warn!("can't decode instruction for {:x}", rip);
                    self.write_gva(cr3, rip, &buffer[..])?;
                }
            }

        }

        if params.save_instructions {
            let buffer = exception_context.InstructionBytes;
            let instruction = self.decode_instruction(&buffer)?;
            let output = self.format_instruction(rip, instruction)?;
            trace.instrs.push(output);
        }

        Ok(true)
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

    fn format_instruction(&mut self, rip: u64, instruction: zydis::DecodedInstruction) -> Result<String> {
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
        formatter.format_instruction(&instruction, &mut buffer, Some(rip as u64), None)?;
        let output = format!("0x{:016X}: {}", rip, buffer);
        Ok(output)
    }

}


impl <S: Snapshot + mem::X64VirtualAddressSpace> Tracer for WhvpTracer <S> {

    fn set_initial_context(&mut self, context: &ProcessorState) -> Result<()> {
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

    fn run(&mut self, params: &Params) -> Result<Trace> {
        let mut exits = 0;
        let mut cancel = 0;

        let mut trace = Trace::new();

        let mut regs = self.partition.get_regs()?;
        let rip = unsafe { regs.rip.Reg64 };
        let cr3 = unsafe { regs.cr3.Reg64 };

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

        if params.save_instructions {
            let mut buffer = [0u8; 16];

            match self.cache.read_gva(cr3, rip as u64, &mut buffer) {
                Ok(()) => {
                    let instruction = self.decode_instruction(&buffer)?;
                    let output = self.format_instruction(rip, instruction)?;
                    trace.instrs.push(output);
                }
                _ => {
                    match self.snapshot.read_gva(cr3, rip as u64, &mut buffer) {
                        Ok(()) => {
                            let instruction = self.decode_instruction(&buffer)?;
                            let output = self.format_instruction(rip, instruction)?;
                            trace.instrs.push(output);
                        },
                        _ => {
                            trace.instrs.push(format!("0x{:016X}: ???", rip));
                        }
                    }
                }
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
                    if !self.handle_memory_access(&params, &memory_access_context, &mut trace)? {
                        break;
                    }
                }
                whvp::ExitContext::Exception(vp_context, exception_context) => {
                    cancel = 0;
                    if !self.handle_exception(&params, &vp_context, &exception_context, &mut trace)? {
                        break;
                    }
                }
                whvp::ExitContext::X64MsrAccess(vp_context, msr_access_context) => {
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
                    error!("unhandled vm exit: {:?}", exit_context);
                    trace.status = EmulationStatus::Error;
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
        self.partition.read_gva(cr3, vaddr, data).context("can't read gva")
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()> {
        self.partition.write_gva(cr3, vaddr, data).context("can't write gva")
    }

    fn cr3(&mut self) -> Result<u64> {
        let context = self.partition.get_regs()?;
        let cr3 = unsafe { context.cr3.Reg64 };
        Ok(cr3)
    }

}

 