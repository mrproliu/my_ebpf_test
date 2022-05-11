#[inline(never)]
fn sqrt() {
    let positive = 4.0_f64;
    loop {
        _ = positive.sqrt();
    }
}

#[inline(never)]
fn main() {
    sqrt()
}