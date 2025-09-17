#[cfg(windows)]
mod win32;
#[cfg(windows)]
pub use win32::try_run;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::try_run;

#[derive(Debug)]
pub struct Fault {
    /// OS agnostic fault that occured
    pub kind: FaultKind,
    /// Memory address of instruction that caused the fault.
    pub fault_source: Option<usize>,
}

/// OS-agnostic categories of runtime faults code can trigger.
#[derive(Debug)]
pub enum FaultKind {
    /// Invalid or forbidden memory access. Includes the invalid memory address.
    Memory(MemoryFault, usize),

    /// Misaligned memory access. Includes the invalid memory address.
    Alignment(AlignmentFault, usize),

    /// Illegal or privileged instruction executed.
    IllegalInstruction(IllegalInstructionFault),

    /// Arithmetic errors like divide by zero or FP traps.
    Arithmetic(ArithmeticFault),

    /// Stack exhaustion or overflow.
    Stack(StackFault),

    /// Breakpoint or trap instruction hit.
    Trap(TrapFault),
}

/// Specific memory access violations.
#[derive(Debug)]
pub enum MemoryFault {
    /// Windows: `EXCEPTION_ACCESS_VIOLATION`
    WindowsExceptionAccessViolation,

    /// Windows: `EXCEPTION_IN_PAGE_ERROR`
    WindowsExceptionInPageError,

    /// Unix: `SIGSEGV`
    UnixSigsegv,

    /// Unix: `SIGBUS`
    UnixSigbus,
}

/// Misaligned access faults.
#[derive(Debug)]
pub enum AlignmentFault {
    /// Windows: `EXCEPTION_DATATYPE_MISALIGNMENT`
    WindowsExceptionDatatypeMisalignment,

    /// Unix: `SIGBUS`
    UnixSigbus,
}

/// Illegal instruction categories.
#[derive(Debug)]
pub enum IllegalInstructionFault {
    /// Windows: `EXCEPTION_ILLEGAL_INSTRUCTION`
    WindowsExceptionIllegalInstruction,

    /// Windows: `EXCEPTION_PRIV_INSTRUCTION`
    WindowsExceptionPrivInstruction,

    /// Unix: `SIGILL`
    UnixSigill,
}

/// Arithmetic exceptions.
#[derive(Debug)]
pub enum ArithmeticFault {
    /// Windows: `EXCEPTION_INT_DIVIDE_BY_ZERO`
    WindowsExceptionIntDivideByZero,

    /// Windows: `EXCEPTION_FLT_DIVIDE_BY_ZERO`
    WindowsExceptionFltDivideByZero,

    /// Windows: `EXCEPTION_FLT_INVALID_OPERATION`
    WindowsExceptionFltInvalidOperation,

    /// Windows: `EXCEPTION_FLT_OVERFLOW`
    WindowsExceptionFltOverflow,

    /// Windows: `EXCEPTION_FLT_UNDERFLOW`
    WindowsExceptionFltUnderflow,

    /// Windows: `EXCEPTION_FLT_DENORMAL_OPERAND`
    WindowsExceptionFltDenormalOperand,

    /// Unix: `SIGFPE`
    UnixSigfpe,
}

/// Stack faults.
#[derive(Debug)]
pub enum StackFault {
    /// Windows: `EXCEPTION_STACK_OVERFLOW`
    WindowsExceptionStackOverflow,
}

/// Trap/breakpoint-related faults.
#[derive(Debug)]
pub enum TrapFault {
    /// Windows: `EXCEPTION_BREAKPOINT`
    WindowsExceptionBreakpoint,

    /// Windows: `EXCEPTION_SINGLE_STEP`
    WindowsExceptionSingleStep,

    /// Unix: `SIGTRAP`
    UnixSigtrap,
}
