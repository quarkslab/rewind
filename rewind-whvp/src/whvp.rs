use std::cmp::min;
use std::error::Error;
use std::ffi::c_void;
use std::fmt;
use std::ptr::null_mut;
use std::slice::from_raw_parts_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time;

use mem::VirtMemError;
use whvp_sys::*;

use rewind_core::mem;

pub type GuestVirtualAddress = u64;
pub type GuestPhysicalAddress = u64;

bitflags! {
    pub struct MapGpaRangeFlags : i32 {
        const None = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagNone;
        const Read = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagRead;
        const Write = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagWrite;
        const Execute = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagExecute;
        const TrackDirtyPages = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagTrackDirtyPages;
    }
}

bitflags! {
    pub struct TranslateGvaFlags : i32 {
        const None = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagNone;
        const ValidateRead = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateRead;
        const ValidateWrite = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateWrite;
        const ValidateExecute = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateExecute;
        const PrivilegeExempt = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagPrivilegeExempt;
        const SetPageTableBits = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagSetPageTableBits;
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum ExceptionType {
    Unknown,
    DebugTrapOrFault = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeDebugTrapOrFault as isize,
    BreakpointTrap = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeBreakpointTrap as isize,
}

#[allow(non_upper_case_globals)]
impl From<u8> for ExceptionType {
    fn from(i: u8) -> Self {
        match i {
            1 => ExceptionType::DebugTrapOrFault,
            3 => ExceptionType::BreakpointTrap,
            _ => ExceptionType::Unknown,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct ExecutionState {
    pub Cpl: u8,
    pub Cr0Pe: bool,
    pub Cr0Am: bool,
    pub EferLma: bool,
    pub DebugActive: bool,
    pub InterruptionPending: bool,
    pub InterruptShadow: bool,
}

impl From<WHV_X64_VP_EXECUTION_STATE> for ExecutionState {
    fn from(i: WHV_X64_VP_EXECUTION_STATE) -> Self {
        unsafe {
            Self {
                Cpl: i.__bindgen_anon_1.Cpl() as u8,
                Cr0Pe: i.__bindgen_anon_1.Cr0Pe() == 1,
                Cr0Am: i.__bindgen_anon_1.Cr0Am() == 1,
                EferLma: i.__bindgen_anon_1.EferLma() == 1,
                DebugActive: i.__bindgen_anon_1.DebugActive() == 1,
                InterruptionPending: i.__bindgen_anon_1.InterruptionPending() == 1,
                InterruptShadow: i.__bindgen_anon_1.InterruptShadow() == 1,
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct VpContext {
    pub ExecutionState: ExecutionState,
    pub InstructionLength: usize,
    pub Cr8: u8,
    pub Cs: SegmentRegister,
    pub Rip: u64,
    pub Rflags: u64,
}

impl From<WHV_VP_EXIT_CONTEXT> for VpContext {
    fn from(i: WHV_VP_EXIT_CONTEXT) -> Self {
        Self {
            ExecutionState: i.ExecutionState.into(),
            InstructionLength: i.InstructionLength() as usize,
            Cr8: i.Cr8(),
            Cs: i.Cs.into(),
            Rip: i.Rip,
            Rflags: i.Rflags,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum ExitContext {
    None(VpContext),

    // Standard exits caused by operations of the virtual processor
    MemoryAccess(VpContext, MemoryAccessContext),
    X64IoPortAccess(VpContext, IoPortAccessContext),
    UnrecoverableException(VpContext),
    InvalidVpRegisterValue(VpContext),
    UnsupportedFeature(VpContext, UnsupportedFeatureContext),
    X64InterruptWindow(VpContext, InterruptionDeliverableContext),
    X64Halt(VpContext),
    // X64ApicEoi(VpContext),

    // Additional exits that can be configured through partition properties
    X64MsrAccess(VpContext, MsrAccessContext),
    X64Cpuid(VpContext, CpuidAccessContext),
    Exception(VpContext, ExceptionContext),

    // Exits caused by the host
    Canceled(VpContext, CanceledContext),
}

#[allow(non_upper_case_globals)]
impl From<WHV_RUN_VP_EXIT_CONTEXT> for ExitContext {
    fn from(i: WHV_RUN_VP_EXIT_CONTEXT) -> Self {
        let vp = VpContext::from(i.VpContext);

        unsafe {
            match i.ExitReason {
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonNone => ExitContext::None(vp),
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess => {
                    ExitContext::MemoryAccess(vp, i.__bindgen_anon_1.MemoryAccess.into())
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64IoPortAccess => {
                    ExitContext::X64IoPortAccess(vp, i.__bindgen_anon_1.IoPortAccess.into())
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnrecoverableException => {
                    ExitContext::UnrecoverableException(vp)
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonInvalidVpRegisterValue => {
                    ExitContext::InvalidVpRegisterValue(vp)
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnsupportedFeature => {
                    ExitContext::UnsupportedFeature(
                        vp,
                        i.__bindgen_anon_1.UnsupportedFeature.into(),
                    )
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64InterruptWindow => {
                    ExitContext::X64InterruptWindow(vp, i.__bindgen_anon_1.InterruptWindow.into())
                },

                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess => {
                    ExitContext::X64MsrAccess(vp, i.__bindgen_anon_1.MsrAccess.into())
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Cpuid => {
                    ExitContext::X64Cpuid(vp, i.__bindgen_anon_1.CpuidAccess.into())
                },
                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonException => {
                    ExitContext::Exception(vp, i.__bindgen_anon_1.VpException.into())
                },

                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonCanceled => {
                    ExitContext::Canceled(vp, i.__bindgen_anon_1.CancelReason.into())
                },

                WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Halt => ExitContext::X64Halt(vp),

                _ => panic!("unknown ExitReason variant when constructing ExitContext"),
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum MemoryAccessType {
    Read = WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessRead as isize,
    Write = WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessWrite as isize,
    Execute = WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessExecute as isize,
}

#[allow(non_upper_case_globals)]
impl From<WHV_MEMORY_ACCESS_TYPE> for MemoryAccessType {
    fn from(i: WHV_MEMORY_ACCESS_TYPE) -> Self {
        match i {
            WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessRead => MemoryAccessType::Read,
            WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessWrite => MemoryAccessType::Write,
            WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessExecute => MemoryAccessType::Execute,
            _ => panic!("unknown variant in MemoryAccessInfo"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct MemoryAccessInfo {
    pub AccessType: MemoryAccessType,
    pub GpaUnmapped: bool,
    pub GvaValid: bool,
}

#[allow(non_upper_case_globals)]
impl From<WHV_MEMORY_ACCESS_INFO> for MemoryAccessInfo {
    fn from(i: WHV_MEMORY_ACCESS_INFO) -> Self {
        unsafe {
            Self {
                AccessType: MemoryAccessType::from(i.__bindgen_anon_1.AccessType() as i32),
                GpaUnmapped: i.__bindgen_anon_1.GpaUnmapped() == 1,
                GvaValid: i.__bindgen_anon_1.GvaValid() == 1,
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct MemoryAccessContext {
    pub InstructionBytes: [u8; 16],
    pub AccessInfo: MemoryAccessInfo,
    pub Gpa: GuestPhysicalAddress,
    pub Gva: GuestVirtualAddress,
}

impl From<WHV_MEMORY_ACCESS_CONTEXT> for MemoryAccessContext {
    fn from(i: WHV_MEMORY_ACCESS_CONTEXT) -> Self {
        let mut b = [0; 16];
        b.copy_from_slice(&i.InstructionBytes[0..16]);

        Self {
            InstructionBytes: b,
            AccessInfo: i.AccessInfo.into(),
            Gpa: i.Gpa,
            Gva: i.Gva,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct IoPortAccessInfo {
    pub IsWrite: bool,
    pub AccessSize: u8,
    pub StringOp: bool,
    pub RepPrefix: bool,
}

impl From<WHV_X64_IO_PORT_ACCESS_INFO> for IoPortAccessInfo {
    fn from(i: WHV_X64_IO_PORT_ACCESS_INFO) -> Self {
        unsafe {
            Self {
                IsWrite: i.__bindgen_anon_1.IsWrite() == 1,
                AccessSize: i.__bindgen_anon_1.IsWrite() as u8,
                StringOp: i.__bindgen_anon_1.StringOp() == 1,
                RepPrefix: i.__bindgen_anon_1.RepPrefix() == 1,
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct SegmentRegister {
    pub Base: u64,
    pub Limit: u32,
    pub Selector: u16,

    pub SegmentType: u8,
    pub NonSystemSegment: bool,
    pub DescriptorPrivilegeLevel: u8,
    pub Present: bool,
    pub Available: bool,
    pub Long: bool,
    pub Default: bool,
    pub Granularity: bool,
}

impl From<WHV_X64_SEGMENT_REGISTER> for SegmentRegister {
    fn from(i: WHV_X64_SEGMENT_REGISTER) -> Self {
        unsafe {
            Self {
                Base: i.Base,
                Limit: i.Limit,
                Selector: i.Selector,

                SegmentType: i.__bindgen_anon_1.__bindgen_anon_1.SegmentType() as u8,
                NonSystemSegment: i.__bindgen_anon_1.__bindgen_anon_1.NonSystemSegment() == 1,
                DescriptorPrivilegeLevel: i
                    .__bindgen_anon_1
                    .__bindgen_anon_1
                    .DescriptorPrivilegeLevel() as u8,
                Present: i.__bindgen_anon_1.__bindgen_anon_1.Present() == 1,
                Available: i.__bindgen_anon_1.__bindgen_anon_1.Available() == 1,
                Long: i.__bindgen_anon_1.__bindgen_anon_1.Long() == 1,
                Default: i.__bindgen_anon_1.__bindgen_anon_1.Default() == 1,
                Granularity: i.__bindgen_anon_1.__bindgen_anon_1.Granularity() == 1,
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct IoPortAccessContext {
    pub InstructionBytes: [u8; 16],
    pub AccessInfo: IoPortAccessInfo,
    pub PortNumber: u16,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub Ds: SegmentRegister,
    pub Es: SegmentRegister,
}

impl From<WHV_X64_IO_PORT_ACCESS_CONTEXT> for IoPortAccessContext {
    fn from(i: WHV_X64_IO_PORT_ACCESS_CONTEXT) -> Self {
        let mut b = [0; 16];
        b.copy_from_slice(&i.InstructionBytes[0..16]);

        Self {
            InstructionBytes: b,
            AccessInfo: i.AccessInfo.into(),
            PortNumber: i.PortNumber,
            Rax: i.Rax,
            Rcx: i.Rcx,
            Rsi: i.Rsi,
            Rdi: i.Rdi,
            Ds: i.Ds.into(),
            Es: i.Es.into(),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum UnsupportedFeatureCode {
    Intercept = WHV_X64_UNSUPPORTED_FEATURE_CODE_WHvUnsupportedFeatureIntercept as isize,
    TaskSwitchTss = WHV_X64_UNSUPPORTED_FEATURE_CODE_WHvUnsupportedFeatureTaskSwitchTss as isize,
}

#[allow(non_upper_case_globals)]
impl From<WHV_X64_UNSUPPORTED_FEATURE_CODE> for UnsupportedFeatureCode {
    fn from(i: WHV_X64_UNSUPPORTED_FEATURE_CODE) -> Self {
        match i {
            WHV_X64_UNSUPPORTED_FEATURE_CODE_WHvUnsupportedFeatureIntercept => {
                UnsupportedFeatureCode::Intercept
            }
            WHV_X64_UNSUPPORTED_FEATURE_CODE_WHvUnsupportedFeatureTaskSwitchTss => {
                UnsupportedFeatureCode::TaskSwitchTss
            }
            _ => panic!("unknown UnsupportedFeatureCode varient when constructing enum"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct UnsupportedFeatureContext {
    pub FeatureCode: UnsupportedFeatureCode,
    pub FeatureParameter: u64,
}

impl From<WHV_X64_UNSUPPORTED_FEATURE_CONTEXT> for UnsupportedFeatureContext {
    fn from(i: WHV_X64_UNSUPPORTED_FEATURE_CONTEXT) -> Self {
        Self {
            FeatureCode: i.FeatureCode.into(),
            FeatureParameter: i.FeatureParameter,
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum PendingInterruptionType {
    Interrupt = WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingInterrupt as isize,
    Nmi = WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingNmi as isize,
    Exception = WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingException as isize,
}

#[allow(non_upper_case_globals)]
impl From<WHV_X64_PENDING_INTERRUPTION_TYPE> for PendingInterruptionType {
    fn from(i: WHV_X64_PENDING_INTERRUPTION_TYPE) -> Self {
        match i {
            WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingInterrupt => {
                PendingInterruptionType::Interrupt
            }
            WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingNmi => PendingInterruptionType::Nmi,
            WHV_X64_PENDING_INTERRUPTION_TYPE_WHvX64PendingException => {
                PendingInterruptionType::Exception
            }
            _ => panic!("unknown PendingInterruptionType variant when constructing enum"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct InterruptionDeliverableContext {
    pub DeliverableType: PendingInterruptionType,
}

impl From<WHV_X64_INTERRUPTION_DELIVERABLE_CONTEXT> for InterruptionDeliverableContext {
    fn from(i: WHV_X64_INTERRUPTION_DELIVERABLE_CONTEXT) -> Self {
        Self {
            DeliverableType: i.DeliverableType.into(),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct MsrAccessInfo {
    pub IsWrite: bool,
}

impl From<WHV_X64_MSR_ACCESS_INFO> for MsrAccessInfo {
    fn from(i: WHV_X64_MSR_ACCESS_INFO) -> Self {
        unsafe {
            Self {
                IsWrite: i.__bindgen_anon_1.IsWrite() == 1,
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct MsrAccessContext {
    pub AccessInfo: MsrAccessInfo,
    pub MsrNumber: u32,
    pub Rax: u64,
    pub Rdx: u64,
}

impl From<WHV_X64_MSR_ACCESS_CONTEXT> for MsrAccessContext {
    fn from(i: WHV_X64_MSR_ACCESS_CONTEXT) -> Self {
        Self {
            AccessInfo: i.AccessInfo.into(),
            MsrNumber: i.MsrNumber,
            Rax: i.Rax,
            Rdx: i.Rdx,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct CpuidAccessContext {
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub DefaultResultRax: u64,
    pub DefaultResultRcx: u64,
    pub DefaultResultRdx: u64,
    pub DefaultResultRbx: u64,
}

impl From<WHV_X64_CPUID_ACCESS_CONTEXT> for CpuidAccessContext {
    fn from(i: WHV_X64_CPUID_ACCESS_CONTEXT) -> Self {
        Self {
            Rax: i.Rax,
            Rcx: i.Rcx,
            Rdx: i.Rdx,
            Rbx: i.Rbx,
            DefaultResultRax: i.DefaultResultRax,
            DefaultResultRcx: i.DefaultResultRcx,
            DefaultResultRdx: i.DefaultResultRdx,
            DefaultResultRbx: i.DefaultResultRbx,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct ExceptionContext {
    pub InstructionBytes: [u8; 16],
    pub SoftwareException: bool,
    pub ExceptionType: u8,
    pub ErrorCode: Option<u32>,
    pub ExceptionParameter: u64,
}

#[allow(non_snake_case)]
impl From<WHV_VP_EXCEPTION_CONTEXT> for ExceptionContext {
    fn from(i: WHV_VP_EXCEPTION_CONTEXT) -> Self {
        let mut b = [0; 16];
        b.copy_from_slice(&i.InstructionBytes[0..16]);

        unsafe {
            let ErrorCode = match i.ExceptionInfo.__bindgen_anon_1.ErrorCodeValid() {
                0 => None,
                _ => Some(i.ErrorCode),
            };

            Self {
                InstructionBytes: b,
                SoftwareException: i.ExceptionInfo.__bindgen_anon_1.SoftwareException() == 1,
                ExceptionType: i.ExceptionType,
                ErrorCode,
                ExceptionParameter: i.ExceptionParameter,
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum CancelReason {
    User = WHV_RUN_VP_CANCEL_REASON_WhvRunVpCancelReasonUser as isize,
}

#[allow(non_upper_case_globals)]
impl From<WHV_RUN_VP_CANCEL_REASON> for CancelReason {
    fn from(i: WHV_RUN_VP_CANCEL_REASON) -> Self {
        match i {
            WHV_RUN_VP_CANCEL_REASON_WhvRunVpCancelReasonUser => CancelReason::User,
            _ => panic!("unknown CancelReason variant when constructing enum"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct CanceledContext {
    pub CancelReason: CancelReason,
}

impl From<WHV_RUN_VP_CANCELED_CONTEXT> for CanceledContext {
    fn from(i: WHV_RUN_VP_CANCELED_CONTEXT) -> Self {
        Self {
            CancelReason: i.CancelReason.into(),
        }
    }
}

#[derive(Debug)]
pub struct PartitionError {
    details: String,
}

impl PartitionError {
    fn new(msg: String) -> PartitionError {
        PartitionError { details: msg }
    }
}

impl fmt::Display for PartitionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for PartitionError {
    fn description(&self) -> &str {
        &self.details
    }
}

const WHV_REGISTER_NAMES: &[i32] = &[
    WHV_REGISTER_NAME_WHvX64RegisterRax,
    WHV_REGISTER_NAME_WHvX64RegisterRcx,
    WHV_REGISTER_NAME_WHvX64RegisterRdx,
    WHV_REGISTER_NAME_WHvX64RegisterRbx,
    WHV_REGISTER_NAME_WHvX64RegisterRsp,
    WHV_REGISTER_NAME_WHvX64RegisterRbp,
    WHV_REGISTER_NAME_WHvX64RegisterRsi,
    WHV_REGISTER_NAME_WHvX64RegisterRdi,
    WHV_REGISTER_NAME_WHvX64RegisterR8,
    WHV_REGISTER_NAME_WHvX64RegisterR9,
    WHV_REGISTER_NAME_WHvX64RegisterR10,
    WHV_REGISTER_NAME_WHvX64RegisterR11,
    WHV_REGISTER_NAME_WHvX64RegisterR12,
    WHV_REGISTER_NAME_WHvX64RegisterR13,
    WHV_REGISTER_NAME_WHvX64RegisterR14,
    WHV_REGISTER_NAME_WHvX64RegisterR15,
    WHV_REGISTER_NAME_WHvX64RegisterRip,
    WHV_REGISTER_NAME_WHvX64RegisterRflags,
    WHV_REGISTER_NAME_WHvX64RegisterEs,
    WHV_REGISTER_NAME_WHvX64RegisterCs,
    WHV_REGISTER_NAME_WHvX64RegisterSs,
    WHV_REGISTER_NAME_WHvX64RegisterDs,
    WHV_REGISTER_NAME_WHvX64RegisterFs,
    WHV_REGISTER_NAME_WHvX64RegisterGs,
    WHV_REGISTER_NAME_WHvX64RegisterLdtr,
    WHV_REGISTER_NAME_WHvX64RegisterTr,
    WHV_REGISTER_NAME_WHvX64RegisterIdtr,
    WHV_REGISTER_NAME_WHvX64RegisterGdtr,
    WHV_REGISTER_NAME_WHvX64RegisterCr0,
    WHV_REGISTER_NAME_WHvX64RegisterCr2,
    WHV_REGISTER_NAME_WHvX64RegisterCr3,
    WHV_REGISTER_NAME_WHvX64RegisterCr4,
    WHV_REGISTER_NAME_WHvX64RegisterCr8,
    WHV_REGISTER_NAME_WHvX64RegisterDr0,
    WHV_REGISTER_NAME_WHvX64RegisterDr1,
    WHV_REGISTER_NAME_WHvX64RegisterDr2,
    WHV_REGISTER_NAME_WHvX64RegisterDr3,
    WHV_REGISTER_NAME_WHvX64RegisterDr6,
    WHV_REGISTER_NAME_WHvX64RegisterDr7,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm0,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm1,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm2,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm3,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm4,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm5,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm6,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm7,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm8,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm9,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm10,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm11,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm12,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm13,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm14,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm15,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx0,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx1,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx2,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx3,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx4,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx5,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx6,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx7,
    // WHV_REGISTER_NAME_WHvX64RegisterFpControlStatus,
    // WHV_REGISTER_NAME_WHvX64RegisterXmmControlStatus,
    // WHV_REGISTER_NAME_WHvX64RegisterTsc,
    WHV_REGISTER_NAME_WHvX64RegisterEfer,
    WHV_REGISTER_NAME_WHvX64RegisterKernelGsBase,
    WHV_REGISTER_NAME_WHvX64RegisterApicBase,
    // WHV_REGISTER_NAME_WHvX64RegisterPat,
    WHV_REGISTER_NAME_WHvX64RegisterSysenterCs,
    WHV_REGISTER_NAME_WHvX64RegisterSysenterEip,
    WHV_REGISTER_NAME_WHvX64RegisterSysenterEsp,
    WHV_REGISTER_NAME_WHvX64RegisterStar,
    WHV_REGISTER_NAME_WHvX64RegisterLstar,
    WHV_REGISTER_NAME_WHvX64RegisterCstar,
    WHV_REGISTER_NAME_WHvX64RegisterSfmask,
    // WHV_REGISTER_NAME_WHvX64RegisterTscAux,
    // WHV_REGISTER_NAME_WHvX64RegisterSpecCtrl,
    // WHV_REGISTER_NAME_WHvX64RegisterPredCmd,
    // WHV_REGISTER_NAME_WHvX64RegisterApicId,
    // WHV_REGISTER_NAME_WHvX64RegisterApicVersion,
    // WHV_REGISTER_NAME_WHvRegisterPendingInterruption,
    WHV_REGISTER_NAME_WHvRegisterInterruptState,
    // WHV_REGISTER_NAME_WHvRegisterPendingEvent,
    // WHV_REGISTER_NAME_WHvX64RegisterDeliverabilityNotifications,
    // WHV_REGISTER_NAME_WHvRegisterInternalActivityState,
    // WHV_REGISTER_NAME_WHvX64RegisterXCr0,
];

#[repr(C, align(64))]
pub struct PartitionContext {
    pub rax: WHV_REGISTER_VALUE,
    pub rcx: WHV_REGISTER_VALUE,
    pub rdx: WHV_REGISTER_VALUE,
    pub rbx: WHV_REGISTER_VALUE,
    pub rsp: WHV_REGISTER_VALUE,
    pub rbp: WHV_REGISTER_VALUE,
    pub rsi: WHV_REGISTER_VALUE,
    pub rdi: WHV_REGISTER_VALUE,
    pub r8: WHV_REGISTER_VALUE,
    pub r9: WHV_REGISTER_VALUE,
    pub r10: WHV_REGISTER_VALUE,
    pub r11: WHV_REGISTER_VALUE,
    pub r12: WHV_REGISTER_VALUE,
    pub r13: WHV_REGISTER_VALUE,
    pub r14: WHV_REGISTER_VALUE,
    pub r15: WHV_REGISTER_VALUE,
    pub rip: WHV_REGISTER_VALUE,

    pub rflags: WHV_REGISTER_VALUE,

    pub es: WHV_REGISTER_VALUE,
    pub cs: WHV_REGISTER_VALUE,
    pub ss: WHV_REGISTER_VALUE,
    pub ds: WHV_REGISTER_VALUE,
    pub fs: WHV_REGISTER_VALUE,
    pub gs: WHV_REGISTER_VALUE,

    pub ldtr: WHV_REGISTER_VALUE,
    pub tr: WHV_REGISTER_VALUE,
    pub idtr: WHV_REGISTER_VALUE,
    pub gdtr: WHV_REGISTER_VALUE,

    pub cr0: WHV_REGISTER_VALUE,
    pub cr2: WHV_REGISTER_VALUE,
    pub cr3: WHV_REGISTER_VALUE,
    pub cr4: WHV_REGISTER_VALUE,
    pub cr8: WHV_REGISTER_VALUE,

    pub dr0: WHV_REGISTER_VALUE,
    pub dr1: WHV_REGISTER_VALUE,
    pub dr2: WHV_REGISTER_VALUE,
    pub dr3: WHV_REGISTER_VALUE,
    pub dr6: WHV_REGISTER_VALUE,
    pub dr7: WHV_REGISTER_VALUE,

    // pub xmm0: WHV_REGISTER_VALUE,
    // pub xmm1: WHV_REGISTER_VALUE,
    // pub xmm2: WHV_REGISTER_VALUE,
    // pub xmm3: WHV_REGISTER_VALUE,
    // pub xmm4: WHV_REGISTER_VALUE,
    // pub xmm5: WHV_REGISTER_VALUE,
    // pub xmm6: WHV_REGISTER_VALUE,
    // pub xmm7: WHV_REGISTER_VALUE,
    // pub xmm8: WHV_REGISTER_VALUE,
    // pub xmm9: WHV_REGISTER_VALUE,
    // pub xmm10: WHV_REGISTER_VALUE,
    // pub xmm11: WHV_REGISTER_VALUE,
    // pub xmm12: WHV_REGISTER_VALUE,
    // pub xmm13: WHV_REGISTER_VALUE,
    // pub xmm14: WHV_REGISTER_VALUE,
    // pub xmm15: WHV_REGISTER_VALUE,

    // pub st0: WHV_REGISTER_VALUE,
    // pub st1: WHV_REGISTER_VALUE,
    // pub st2: WHV_REGISTER_VALUE,
    // pub st3: WHV_REGISTER_VALUE,
    // pub st4: WHV_REGISTER_VALUE,
    // pub st5: WHV_REGISTER_VALUE,
    // pub st6: WHV_REGISTER_VALUE,
    // pub st7: WHV_REGISTER_VALUE,

    // pub fp_control:  WHV_REGISTER_VALUE,
    // pub xmm_control: WHV_REGISTER_VALUE,

    // pub tsc: WHV_REGISTER_VALUE,
    pub efer: WHV_REGISTER_VALUE,
    pub kernel_gs_base: WHV_REGISTER_VALUE,
    pub apic_base: WHV_REGISTER_VALUE,
    // pub pat: WHV_REGISTER_VALUE,
    pub sysenter_cs: WHV_REGISTER_VALUE,
    pub sysenter_eip: WHV_REGISTER_VALUE,
    pub sysenter_esp: WHV_REGISTER_VALUE,
    pub star: WHV_REGISTER_VALUE,
    pub lstar: WHV_REGISTER_VALUE,
    pub cstar: WHV_REGISTER_VALUE,
    pub sfmask: WHV_REGISTER_VALUE,

    // pub tsc_aux: WHV_REGISTER_VALUE,
    // pub spec_ctrl: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub pred_cmd: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub apic_id: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub apic_version: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub pending_interruption: WHV_REGISTER_VALUE,
    pub interrupt_state: WHV_REGISTER_VALUE,
    // pub pending_event: WHV_REGISTER_VALUE,
    // pub deliverability_notifications: WHV_REGISTER_VALUE,
    // pub internal_activity_state: WHV_REGISTER_VALUE, unknown type

    // pub xcr0: WHV_REGISTER_VALUE,
}

impl std::fmt::Display for PartitionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        unsafe {
            write!(
                f,
                "rax {:016x} rcx {:016x} rdx {:016x} rbx {:016x}\n\
                 rsp {:016x} rbp {:016x} rsi {:016x} rdi {:016x}\n\
                 r8  {:016x} r9  {:016x} r10 {:016x} r11 {:016x}\n\
                 r12 {:016x} r13 {:016x} r14 {:016x} r15 {:016x}\n\
                 rip {:016x}\n\
                 rflags {:016x}\n\
                 ",
                self.rax.Reg64,
                self.rcx.Reg64,
                self.rdx.Reg64,
                self.rbx.Reg64,
                self.rsp.Reg64,
                self.rbp.Reg64,
                self.rsi.Reg64,
                self.rdi.Reg64,
                self.r8.Reg64,
                self.r9.Reg64,
                self.r10.Reg64,
                self.r11.Reg64,
                self.r12.Reg64,
                self.r13.Reg64,
                self.r14.Reg64,
                self.r15.Reg64,
                self.rip.Reg64,
                self.rflags.Reg64,
            )
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
    pub addr: usize,
}

#[derive(Debug)]
pub struct Partition {
    handle: WHV_PARTITION_HANDLE,
    virtual_processors: Vec<u32>,
    pub mapped_regions: Vec<MemoryRegion>,
}

impl Partition {
    pub fn new() -> Result<Self, PartitionError> {
        let handle = create_partition()?;

        let mut partition = Partition {
            handle,
            virtual_processors: Vec::new(),
            mapped_regions: Vec::new(),
        };

        // FIXME in args
        let proc_count = 1u32;
        partition.set_processor_count(proc_count)?;

        partition.set_extended_vm_exits()?;

        // FIXME in args
        // let vmexit_bitmap: u64 = (1 << 1) | (1 << 14);
        let vmexit_bitmap: u64 = (1 << 1) | (1 << 3);
        partition.set_exception_bitmap(vmexit_bitmap)?;

        partition.setup_partition()?;

        partition.create_processor()?;

        let partition_handle = handle as usize;

        std::thread::spawn(move || keep_alive_thread(partition_handle));

        Ok(partition)
    }

    fn set_processor_count(&mut self, proc_count: u32) -> Result<(), PartitionError> {
        let hr = unsafe {
            WHvSetPartitionProperty(
                self.handle,
                WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeProcessorCount,
                &proc_count as *const u32 as *const c_void,
                std::mem::size_of_val(&proc_count) as u32,
            )
        };
        match hr {
            0 => { Ok(()) },
            _ => {
                let msg = format!("WHvSetPartitionProperty failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    fn set_extended_vm_exits(&mut self) -> Result<(), PartitionError> {
        let mut exits: WHV_EXTENDED_VM_EXITS = unsafe { std::mem::zeroed() };
        unsafe {
            exits.__bindgen_anon_1.set_ExceptionExit(1);
            exits.__bindgen_anon_1.set_X64MsrExit(1);
            // exits.__bindgen_anon_1.set_X64CpuidExit(1);
        }
        let hr = unsafe {
            WHvSetPartitionProperty(
                self.handle,
                WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExtendedVmExits,
                &exits as *const WHV_EXTENDED_VM_EXITS as *const c_void,
                std::mem::size_of_val(&exits) as u32,
            )
        };
        match hr {
            0 => { Ok(()) },
            _ => {
                let msg = format!("WHvSetPartitionProperty failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    fn set_exception_bitmap(&mut self, bitmap: u64) -> Result<(), PartitionError> {
        let hr = unsafe {
            WHvSetPartitionProperty(
                self.handle,
                WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExceptionExitBitmap,
                &bitmap as *const u64 as *const c_void,
                std::mem::size_of_val(&bitmap) as u32,
            )
        };
        match hr {
            0 => Ok(()),
            _ => {
                let msg = format!("WHvSetPartitionProperty failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    fn setup_partition(&mut self) -> Result<(), PartitionError> {
        let hr = unsafe { WHvSetupPartition(self.handle) };
        match hr {
            0 => Ok(()),
            _ => {
                let msg = format!("WHvSetupPartition failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    fn create_processor(&mut self) -> Result<(), PartitionError> {
        let hr = unsafe { WHvCreateVirtualProcessor(self.handle, 0, 0) };
        match hr {
            0 => {
                self.virtual_processors.push(0);
                Ok(())
            }
            _ => {
                let msg = format!("WHvCreateVirtualProcessor failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    // FIXME: overkill to get full context, need another way
    pub fn get_regs(&mut self) -> Result<PartitionContext, PartitionError> {
        let mut context: PartitionContext = unsafe { std::mem::zeroed() };

        let hr = unsafe {
            WHvGetVirtualProcessorRegisters(
                self.handle,
                0,
                WHV_REGISTER_NAMES.as_ptr(),
                WHV_REGISTER_NAMES.len() as u32,
                &mut context as *mut PartitionContext as *mut WHV_REGISTER_VALUE,
            )
        };

        match hr {
            0 => Ok(context),
            _ => {
                let msg = format!("WHvGetVirtualProcessorRegisters failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn set_regs(&mut self, context: &PartitionContext) -> Result<(), PartitionError> {
        let hr = unsafe {
            WHvSetVirtualProcessorRegisters(
                self.handle,
                0,
                WHV_REGISTER_NAMES.as_ptr(),
                WHV_REGISTER_NAMES.len() as u32,
                context as *const PartitionContext as *const WHV_REGISTER_VALUE,
            )
        };

        match hr {
            0 => Ok(()),
            _ => {
                let msg = format!("WHvSetVirtualProcessorRegisters failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn map_physical_memory(
        &mut self,
        addr: usize,
        buffer: usize,
        length: usize,
        perm: i32,
    ) -> Result<(), PartitionError> {
        let hr = unsafe {
            WHvMapGpaRange(
                self.handle,
                buffer as *mut c_void,
                addr as u64,
                length as u64,
                perm | WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagTrackDirtyPages,
            )
        };
        match hr {
            0 => {
                let region = MemoryRegion {
                    base: addr,
                    size: length,
                    addr: buffer,
                };
                self.mapped_regions.push(region);
                Ok(())
            }
            _ => {
                let msg = format!("WHvMapGpaRange failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    #[allow(dead_code)]
    pub fn unmap_physical_memory(
        &mut self,
        addr: usize,
        size: usize,
    ) -> Result<(), PartitionError> {
        let hr = unsafe { WHvUnmapGpaRange(self.handle, addr as u64, size as u64) };
        match hr {
            0 => {
                self.mapped_regions.retain(|region| {
                    !(region.base <= addr
                        && addr < region.base + region.size
                        && region.base <= addr + size
                        && addr + size <= region.base + region.size)
                });
                Ok(())
            }
            _ => {
                let msg = format!("WHvUnmapGpaRange failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn query_gpa_range(&mut self, addr: usize, size: usize) -> Result<u64, PartitionError> {
        let mut bitmap: u64 = 0;
        let hr = unsafe {
            WHvQueryGpaRangeDirtyBitmap(
                self.handle,
                addr as u64,
                size as u64,
                &mut bitmap as *mut u64,
                std::mem::size_of_val(&bitmap) as u32,
            )
        };
        match hr {
            0 => Ok(bitmap),
            _ => {
                let msg = format!("WHvQueryGpaRangeDirtyBitmap failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn flush_gpa_range(&mut self, addr: usize, size: usize) -> Result<(), PartitionError> {
        let hr = unsafe {
            WHvQueryGpaRangeDirtyBitmap(self.handle, addr as u64, size as u64, std::ptr::null_mut::<u64>(), 0)
        };
        match hr {
            0 => Ok(()),
            _ => {
                let msg = format!("WHvQueryGpaRangeDirtyBitmap failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn read_physical_memory(&self, addr: usize, size: usize) -> Result<&[u8], PartitionError> {
        // FIXME: handle crossing regions reads
        let region = self.get_region(addr, size);
        match region {
            Some(region) => {
                let offset = addr - region.base;
                let region_addr = region.addr + offset;
                let slice: &[u8] = unsafe { from_raw_parts_mut(region_addr as *mut u8, size) };
                Ok(slice)
            }
            None => {
                let msg = format!("can't find region {:x}", addr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn write_physical_memory(
        &mut self,
        addr: usize,
        data: &[u8],
    ) -> Result<usize, PartitionError> {
        // FIXME: handle crossing regions writes
        let region = self.get_region(addr, data.len());
        match region {
            Some(region) => {
                let offset = addr - region.base;

                let slice: &mut [u8] =
                    unsafe { from_raw_parts_mut(region.addr as *mut u8, region.size) };
                let pos = 0usize;
                let remaining_region_size = region.size.saturating_sub(offset);

                let size = min(data.len() - pos, remaining_region_size);
                slice[offset..offset + size].copy_from_slice(&data[pos..pos + size]);
                Ok(size)
            }
            None => {
                let msg = format!("can't find region {:x}", addr);
                Err(PartitionError::new(msg))
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_physical_memory_valid(&mut self, addr: usize, size: usize) -> bool {
        let region = self.get_region(addr, size);
        region.is_some()
    }

    fn get_region(&self, addr: usize, size: usize) -> Option<&MemoryRegion> {
        let region = self.mapped_regions.iter().find(|region| {
            region.base <= addr
                && addr < region.base + region.size
                && region.base <= addr + size
                && addr + size <= region.base + region.size
        });
        region
    }

    #[allow(dead_code)]
    pub fn translate_virtual_address(&mut self, addr: usize) -> Result<u64, PartitionError> {
        let flags = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateRead;
        let mut result: WHV_TRANSLATE_GVA_RESULT = unsafe { std::mem::zeroed() };
        let mut gpa: u64 = 0;
        let hr = unsafe {
            WHvTranslateGva(
                self.handle,
                0,
                addr as u64,
                flags,
                &mut result as *mut WHV_TRANSLATE_GVA_RESULT,
                &mut gpa as *mut u64,
            )
        };
        match hr {
            0 => match result.ResultCode {
                WHV_TRANSLATE_GVA_RESULT_CODE_WHvTranslateGvaResultSuccess => Ok(gpa),
                _ => {
                    let msg = format!("WHvTranslateGva failed: code {:#x}", result.ResultCode);
                    Err(PartitionError::new(msg))
                }
            },
            _ => {
                let msg = format!("WHvTranslateGva failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }

    pub fn run(&mut self) -> Result<WHV_RUN_VP_EXIT_CONTEXT, PartitionError> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = unsafe { std::mem::zeroed() };
        KEEP_ALIVE_THREAD_ACTIVE.store(1, Ordering::SeqCst);
        let hr = unsafe {
            WHvRunVirtualProcessor(
                self.handle,
                0,
                &mut exit_context as *mut WHV_RUN_VP_EXIT_CONTEXT as *mut c_void,
                std::mem::size_of_val(&exit_context) as u32,
            )
        };
        KEEP_ALIVE_THREAD_ACTIVE.store(0, Ordering::SeqCst);
        match hr {
            0 => Ok(exit_context),
            _ => {
                let msg = format!("WHvRunVirtualProcessor failed with {:#x}", hr);
                Err(PartitionError::new(msg))
            }
        }
    }
}

impl mem::X64VirtualAddressSpace for Partition {
    fn read_gpa(&self, gpa: mem::Gpa, buf: &mut [u8]) -> Result<(), VirtMemError> {
        let (_base, _off) = mem::page_off(gpa);
        let data = self.read_physical_memory(gpa as usize, buf.len());
        match data {
            Ok(arr) => {
                buf.copy_from_slice(&arr[..buf.len()]);
                Ok(())
            }
            Err(e) => Err(VirtMemError::GenericError(e.to_string()))
            // mem::VirtMemError::MissingPage(base))),
        }
    }

    fn write_gpa(&mut self, gpa: mem::Gpa, data: &[u8]) -> Result<(), VirtMemError> {
        let (base, _off) = mem::page_off(gpa);
        let result = self.write_physical_memory(gpa as usize, data);

        match result {
            Ok(_size) => Ok(()),
            _ => Err(mem::VirtMemError::MissingPage(base)),
        }
    }
}

impl Drop for Partition {
    fn drop(&mut self) {
        debug!("destructing partition");
        for &pid in &self.virtual_processors {
            let res = unsafe { WHvDeleteVirtualProcessor(self.handle, pid) };
            assert!(res == 0, "WHvDeleteVirtualProcessor() error: {:#x}", res);
        }

        let res = unsafe { WHvDeletePartition(self.handle) };
        assert!(res == 0, "WHvDeletePartition() error: {:#x}", res);
        // FIXME: unmap regions
    }
}

static KEEP_ALIVE_THREAD_ACTIVE: AtomicUsize = AtomicUsize::new(0);

fn keep_alive_thread(handle: usize) {
    let handle = handle as WHV_PARTITION_HANDLE;
    let delay = time::Duration::from_millis(50);

    loop {
        thread::sleep(delay);

        if KEEP_ALIVE_THREAD_ACTIVE.load(Ordering::SeqCst) == 0 {
            continue;
        }

        unsafe {
            WHvCancelRunVirtualProcessor(handle, 0, 0);
        }
    }
}

// pub fn get_capability() -> BOOL {
//     let code = WHV_CAPABILITY_CODE_WHvCapabilityCodeHypervisorPresent;
//     let mut capability = unsafe { std::mem::zeroed::<WHV_CAPABILITY>() };
//     let mut size = 0u32;
//     let _hr = unsafe {
//         WHvGetCapability(
//             code,
//             &mut capability as *mut WHV_CAPABILITY as *mut c_void,
//             std::mem::size_of::<WHV_CAPABILITY>() as u32,
//             &mut size,
//         )
//     };
//     unsafe { capability.HypervisorPresent }
// }

pub fn create_partition() -> Result<WHV_PARTITION_HANDLE, PartitionError> {
    let mut partition: WHV_PARTITION_HANDLE = null_mut();
    let hr = unsafe { WHvCreatePartition(&mut partition) };
    match hr {
        0 => Ok(partition),
        _ => {
            let msg = format!("WHvCreatePartition failed with {:#x}", hr);
            Err(PartitionError::new(msg))
        }
    }
}

#[allow(dead_code)]
fn set_dr7(mut dr7: u64, slot: u8) -> u64 {
    dr7 |= 1 << (slot * 2);

    let condition = 0; // HW_EXECUTE
                       // set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
    dr7 |= condition << ((slot * 4) + 16);

    let length = 0;
    // set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
    dr7 |= length << ((slot * 4) + 18);
    dr7
}

#[allow(dead_code)]
fn clear_dr7(mut dr7: u64, slot: u8) -> u64 {
    dr7 &= !(1 << (slot * 2));
    // remove the condition (RW0 - RW3) field from the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
    dr7 &= !(3 << ((slot * 4) + 16));

    // remove the length (LEN0-LEN3) field from the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
    dr7 &= !(3 << ((slot * 4) + 18));
    dr7
}

#[allow(dead_code)]
fn set_hw_breakpoint(context: &mut PartitionContext, address: u64) {
    let slot = 0;
    context.dr0.Reg64 = address;
    let dr7 = unsafe { context.dr7.Reg64 };
    context.dr7.Reg64 = set_dr7(dr7, slot);
}
