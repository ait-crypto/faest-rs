//! Timing helper for explicitly requested, ignored component benchmarks.
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

pub(crate) fn measure(name: &str, mut run: impl FnMut()) {
    let mut samples = [0.0f64; 5];
    for sample in &mut samples {
        let start = Instant::now();
        let mut count = 0;
        while start.elapsed() < Duration::from_millis(100) {
            run();
            count += 1;
        }
        *sample = start.elapsed().as_secs_f64() * 1e9 / black_box(count) as f64;
    }
    samples.sort_by(f64::total_cmp);
    std::println!("{name}: {:.0} ns/op", samples[2]);
}
