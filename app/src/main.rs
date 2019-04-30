#![no_std]
#![no_main]
#![feature(asm)]

use rt::entry;
use rt::Vector;
use cortex_m_semihosting::{debug, hio::{self, HStdout}};
use core::slice::from_raw_parts_mut;
use embedded_hal::serial::{Read, Write};

macro_rules! stack_allocate {
    () => {{
        #[link_section = ".uninit"]
        static mut STACK: [u8; 1024] = [0; 1024];

        unsafe { &STACK[0] as *const u8 as u32 + 1024 }
    }};
}

struct Process<'a> {
    sp: *mut u8,
    regs: &'a [u32; 8],
}

impl<'a> Process<'a> {
    fn create(entry: u32, sp: u32, regs: &'a [u32; 8]) -> Process {
        let base_frame_ptr = (sp - 0x20) as *mut u32;
        let base_frame = unsafe { from_raw_parts_mut(base_frame_ptr, 8) };
        base_frame[0] = 0; // r0
        base_frame[1] = 2; // r1
        base_frame[2] = 0; // r2
        base_frame[3] = 0; // r3
        base_frame[4] = 0; // r12
        base_frame[5] = 0; // lr(r14)
        base_frame[6] = entry; // return address
        base_frame[7] = 0x01000000; // xpsr, set thumb state
        Process {
            sp: base_frame_ptr as *mut u8,
            regs: regs,
        }
    }
}

entry!(main);

// copied from https://github.com/tock/tock
macro_rules! static_init {
    ($T:ty, $e:expr) => {
        // Ideally we could use mem::size_of<$T>, uninitialized or zerod here
        // instead of having an `Option`, however that is not currently possible
        // in Rust, so in some cases we're wasting up to a word.
        {
            use core::{mem, ptr};
            // Statically allocate a read-write buffer for the value, write our
            // initial value into it (without dropping the initial zeros) and
            // return a reference to it.
            static mut BUF: Option<$T> = None;
            let tmp : &'static mut $T = mem::transmute(&mut BUF);
            ptr::write(tmp as *mut $T, $e);
            tmp
        };
    }
}

pub fn main() -> ! {
    let address = stack_allocate!();
    let regs = [0u32; 8];

    let mut process = Process::create(app_main as u32, address, &regs);

    loop {
        unsafe {
            asm!(
                "
                msr psp, $0
                ldmia $2, {r4-r11}
                svc 0
                stmia $2, {r4-r11}
                mrs $0, psp
                "
                :"={r0}"(process.sp): "{r0}"(process.sp),"{r1}"(process.regs)
                :"r4","r5","r6","r7","r8","r9","r10","r11":"volatile"
            );
        }
    }

    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

#[no_mangle]
pub unsafe extern "C" fn app_main(_r0: usize, _r1: usize, _r2: usize) -> ! {
    asm!("svc 1"::::"volatile");
    loop {}
}

