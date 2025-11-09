use async_port_scanner::Scanner;
use std::sync::Arc;
use std::time::Duration;
use std::{env, u32};
use tokio::task::JoinSet;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let limiter: u32 = 20000;
    let parallel: u32 = 5000;
    let amt = limiter / parallel;
    adjust_ulimit_size(limiter as u64);
    let ps = Scanner::new(Duration::from_secs(1));
    let arc_ps = Arc::new(ps);
    let mut handles = JoinSet::new();
    let args: Vec<String> = env::args().collect();
    let c = args[1].parse::<u8>().unwrap();
    for d in 0..255 {
        let cloned_ps = Arc::clone(&arc_ps);
        let _ = handles.spawn(async move {
            let host = format! {"{}{}.{}", "0.0.", c, d};
            println! {"{}", host};
            cloned_ps.run_batched(host, 1, 49151, parallel).await
        });
        if (d % amt) == 0 && (d != 0) {
            while let Some(res) = handles.join_next().await {
                let res = res.unwrap();
                println! {"{:?}", res};
            }
        }
    }
}

fn adjust_ulimit_size(size: u64) -> u64 {
    use rlimit::Resource;
    if Resource::NOFILE.set(size, size).is_ok() {
        println!("Automatically increasing ulimit value to {size}.");
    } else {
        println!("ERROR. Failed to set ulimit value");
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft
}
