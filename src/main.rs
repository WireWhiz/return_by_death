use libc::{SA_SIGINFO, SIG_DFL, SIGSEGV, c_int, sigaction, sigemptyset, siginfo_t, strsignal};
use setjmp::{sigjmp_buf, siglongjmp, sigsetjmp};
use std::cell::RefCell;
use std::ffi::c_void;
use std::io::{self, Write};

thread_local! {
    static RECOVER_CTX: RefCell<Option<sigjmp_buf>> = RefCell::new(None);
}

unsafe extern "C" fn sig_handler(sig: c_int, info: *const siginfo_t, _user_context: *mut c_void) {
    unsafe {
        println!(
            "Signal {}: \"{:?}\" intercepted at address {:x}",
            sig,
            std::ffi::CStr::from_ptr(strsignal(sig)),
            (*info).si_addr() as usize
        );
        if let Some(mut ctx) = RECOVER_CTX.with(|ctx| ctx.borrow_mut().take()) {
            println!("Trying to recover");
            siglongjmp(&mut ctx, sig);
        } else {
            println!("No jump ctx");
        }
    }
}

fn main() {
    println!("Hello world!");
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = sig_handler as usize;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            eprintln!("sigaction install failed");
        }
        println!("Handler set");

        let mut new_jmp = std::mem::zeroed();
        let res = sigsetjmp(&mut new_jmp, 1);
        println!("sigsetjmp res was {}", res);
        let res = if res != 0 {
            println!("Jump was from error");
            Err(res)
        } else {
            RECOVER_CTX.set(Some(new_jmp));
            println!("Set checkpoint");
            Ok(())
        };

        println!("checkpoint returned: {:?}", res);
        match res {
            Err(sig) => {
                println!(
                    "*Return by death.wav* you remember you were slain by \"{:?}\"",
                    std::ffi::CStr::from_ptr(strsignal(sig))
                )
            }
            Ok(()) => {
                println!("angering the coding gods");
                *std::ptr::null_mut() = 0;
            }
        }

        // Reset to default handler
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = SIG_DFL;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);

        if libc::sigaction(SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            eprintln!("sigaction reset failed");
        }

        println!("Code finished");
        io::stdout().flush().unwrap();
    }
}
