//! Deliberately invalid test-only binary. CI requires a genuine ASan diagnostic/nonzero exit.
fn main() {
    let allocation = Box::new([std::hint::black_box(42u8)]);
    let index = std::hint::black_box(16usize);
    // Intentional positive control; never linked into a parser, product or ordinary smoke target.
    let value = unsafe { std::ptr::read_volatile(allocation.as_ptr().add(index)) };
    std::hint::black_box(value);
}
