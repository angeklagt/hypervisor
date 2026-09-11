use core::arch::asm;
use core::fmt::{self, Write};

const COM1: u16 = 0x3f8;

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x01);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

pub fn log_line(message: &str) {
    let mut serial = Serial;
    let _ = writeln!(serial, "{message}");
}

pub fn log_hex(label: &str, value: u64) {
    let mut serial = Serial;
    let _ = writeln!(serial, "{label}0x{value:016x}");
}

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            if byte == b'\n' {
                write_byte(b'\r');
            }
            write_byte(byte);
        }
        Ok(())
    }
}

fn write_byte(byte: u8) {
    const SPIN_LIMIT: usize = 1_000_000;
    for _ in 0..SPIN_LIMIT {
        if unsafe { inb(COM1 + 5) } & 0x20 != 0 {
            unsafe { outb(COM1, byte) };
            return;
        }
        core::hint::spin_loop();
    }
}

unsafe fn outb(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) }
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack)) };
    value
}

