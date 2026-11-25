//! Positive control for heap_handoff.rs: the same calls, but every response is leaked on purpose
//! with mem::forget. The measurement must see exactly those 140 leaked blocks, which proves the
//! heap test would catch a real leak.
#![forbid(unsafe_code)]

mod heap_common;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn a_deliberate_leak_is_seen() {
    let reqs = heap_common::requests();
    let _profiler = dhat::Profiler::builder().testing().build();
    heap_common::check_fixtures(&reqs);
    for r in &reqs {
        std::hint::black_box(byoai_chain::call_json(r));
    }
    let before = dhat::HeapStats::get();
    for _ in 0..20 {
        for r in &reqs {
            std::mem::forget(byoai_chain::call_json(r));
        }
    }
    let after = dhat::HeapStats::get();
    dhat::assert_eq!(after.curr_blocks - before.curr_blocks, 140, "exactly the 140 leaked responses");
    dhat::assert!(after.curr_bytes > before.curr_bytes);
    println!("HEAP_CONTROL_OK leaked_blocks={}", after.curr_blocks - before.curr_blocks);
}
