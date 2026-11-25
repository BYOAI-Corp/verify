//! Heap check for the handoff path, replacing valgrind (which cannot start on Arch without
//! fetching glibc debug symbols over the network). Every handoff-path file forbids unsafe code, so
//! the compiler rules out use-after-free and overruns; what safe Rust still allows is a leak.
//! This runs 140 verify/taint calls (incl. error paths) and requires the live heap to return to
//! exactly where it was. One heap test per file: dhat allows one profiler per process.
#![forbid(unsafe_code)]

mod heap_common;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn handoff_calls_leave_nothing_on_the_heap() {
    let reqs = heap_common::requests();
    let _profiler = dhat::Profiler::builder().testing().build();
    heap_common::check_fixtures(&reqs);
    for r in &reqs {
        std::hint::black_box(byoai_chain::call_json(r)); // warm-up: any one-time setup
    }
    let before = dhat::HeapStats::get();
    for _ in 0..20 {
        for r in &reqs {
            std::hint::black_box(byoai_chain::call_json(r));
        }
    }
    let after = dhat::HeapStats::get();
    dhat::assert!(after.total_blocks > before.total_blocks + 140, "the calls really allocated");
    dhat::assert_eq!(after.curr_blocks, before.curr_blocks, "live blocks after 140 calls");
    dhat::assert_eq!(after.curr_bytes, before.curr_bytes, "live bytes after 140 calls");
    // read by the release script (cargo test -- --nocapture) and recorded in the seal
    println!(
        "HEAP_OK calls=140 live_blocks={}->{} live_bytes={}->{} allocations={}",
        before.curr_blocks, after.curr_blocks, before.curr_bytes, after.curr_bytes,
        after.total_blocks - before.total_blocks
    );
}
