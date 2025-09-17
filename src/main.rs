use std::cell::RefCell;
use std::io::{self, Write};
use windows::Win32::Foundation::{NTSTATUS, STATUS_ACCESS_VIOLATION};
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
    EXCEPTION_POINTERS, RemoveVectoredExceptionHandler, RtlCaptureContext,
};

thread_local! {
    static RECOVER_CTX: RefCell<Option<CONTEXT>> = RefCell::new(None);
    static RECOVER_ERR: RefCell<Option<NTSTATUS>> = RefCell::new(None);
}

// VEH handler (runs in context of faulting thread)
unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    unsafe {
        let record = (*exception_info).ExceptionRecord;
        // EXCEPTION/STATUS_ACCESS_VIOLATION = 0xC0000005
        let code = (*record).ExceptionCode;
        println!(
            "Exception code {:x} on thread {}",
            code.0,
            std::mem::transmute::<_, u64>(std::thread::current().id())
        );
        if let Some(ctx) = RECOVER_CTX.with(|ctx| ctx.borrow_mut().take()) {
            RECOVER_ERR.with(|re| *re.borrow_mut() = Some(code));
            /*RECOVER_MSG.set(Some(format!(
                "recover error set to {:x}",
                RECOVER_ERR.get().unwrap().0
            )));*/

            io::stdout().flush().unwrap();
            //RtlRestoreContext(&ctx, None);
            *(*exception_info).ContextRecord = ctx;
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            println!("No jump ctx");
        }
        if code.0 == STATUS_ACCESS_VIOLATION.0 {
            // Attempt to GOTO to thread-local recovery context if initalized
            println!("Is status violation");
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

#[repr(align(16))]
#[derive(Default, Clone, Copy)]
struct AlignedContext(pub CONTEXT);

fn main() {
    println!("Hello world!");
    unsafe {
        let handler_handle = AddVectoredExceptionHandler(1, Some(veh_handler));
        if handler_handle.is_null() {
            panic!("Failed to add exception handler!");
        }
        println!("Handler set");

        let mut return_ctx = AlignedContext::default();
        /*println!(
            "ctx ref: {:x}",
            (&return_ctx) as *const AlignedContext as usize
        );*/
        RtlCaptureContext(&mut return_ctx.0);
        RECOVER_CTX.with(|ctx| *ctx.borrow_mut() = Some(return_ctx.0));

        match RECOVER_ERR.with(|re| re.borrow_mut().take()) {
            Some(err) => std::hint::black_box(println!(
                "*Return by death.wav* you remember you were slain by \"{}\"",
                std::hint::black_box(err).to_hresult().message(),
            )),
            None => {
                println!(
                    "Checkpoint set on {:?}",
                    std::mem::transmute::<_, u64>(std::thread::current().id())
                );

                RECOVER_CTX.with(|ctx| {
                    println!(
                        "{}",
                        if ctx.borrow().is_some() {
                            "Some"
                        } else {
                            "None"
                        }
                    )
                });
                io::stdout().flush().expect("FLUSH");

                let value = RECOVER_CTX.with(|ctx| {
                    if ctx.borrow().is_some() {
                        "Some"
                    } else {
                        "None"
                    }
                });
                *std::ptr::null_mut() = value;
            }
        }
        io::stdout().flush().unwrap();

        RemoveVectoredExceptionHandler(handler_handle);

        println!("Code finished");
        io::stdout().flush().unwrap();
    }
}
