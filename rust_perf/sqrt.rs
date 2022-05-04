
#[inline(never)]
fn sqrt1() {
    let positive = 4.0_f64;
    loop {
        _ = positive.sqrt();
    }
}

#[inline(never)]
fn sqrt() {
    sqrt1()
}

#[inline(never)]
fn main() {
    sqrt()
}