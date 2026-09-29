//! Binary entry: parse flags, wire the local replay station, seed the demo
//! scenario and start two queue workers plus the operations web server.

use std::sync::Arc;
use std::time::Duration;

use webhook_replay::worker::Worker;
use webhook_replay::{build, BuildOptions};
use webhook_replay::service::seed_demo;
use webhook_replay::web;

struct Args {
    listen: String,
    receiver: String,
    db: String,
    key_file: String,
    lease_ms: i64,
    seed: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        listen: "127.0.0.1:5205".to_string(),
        receiver: "127.0.0.1:5206".to_string(),
        db: "webhook-replay.db".to_string(),
        key_file: "webhook-replay.masterkey".to_string(),
        lease_ms: 15_000,
        seed: true,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        let value = |name: &str, iter: &mut dyn Iterator<Item = String>| -> String {
            iter.next().unwrap_or_else(|| {
                eprintln!("error: option {name} requires a value");
                std::process::exit(2);
            })
        };
        match arg.as_str() {
            "--listen" => args.listen = value("--listen", &mut iter),
            "--receiver" => args.receiver = value("--receiver", &mut iter),
            "--db" => args.db = value("--db", &mut iter),
            "--master-key-file" => args.key_file = value("--master-key-file", &mut iter),
            "--lease-ms" => {
                let v = value("--lease-ms", &mut iter);
                args.lease_ms = v.parse().unwrap_or(15_000);
            }
            "--no-seed" => args.seed = false,
            "--help" | "-h" => {
                println!("Webhook 重放站");
                println!("Usage: webhook-replay [--listen 127.0.0.1:5205] [--receiver 127.0.0.1:5206]");
                println!("       [--db PATH] [--master-key-file PATH] [--lease-ms N] [--no-seed]");
                std::process::exit(0);
            }
            other => {
                eprintln!("warning: ignoring unknown argument {other}");
            }
        }
    }
    args
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();

    let built = build(BuildOptions {
        db_path: &args.db,
        master_key_path: &args.key_file,
        receiver_listen: &args.receiver,
        clock: None,
        lease_ms: args.lease_ms,
    })?;

    let app = Arc::new(built.app);

    if args.seed {
        let already = app.store.meta_get("seeded")?;
        if already.is_none() {
            seed_demo(&app)?;
            app.store.meta_set("seeded", "true")?;
            println!("已预置演示场景：端点模式 fail_twice（前两次 503，第三次 200）。");
        }
    }

    // Two workers concurrently contend on leases; the dispatch gate +
    // immediate transaction guarantee a generation is sent by one at a time.
    let request_timeout = Duration::from_secs(2);
    let pump_interval = Duration::from_millis(100);
    for _ in 0..2 {
        let w = Arc::new(Worker::new(
            Arc::clone(&built.queue),
            Arc::clone(&built.store),
            Arc::clone(&built.clock),
            request_timeout,
        ));
        webhook_replay::worker::spawn_pump(w, pump_interval);
    }

    let web_addr = web::start(&args.listen, Arc::clone(&app))?;
    println!("Webhook 重放站已启动");
    println!("  操作页面 / API : http://{web_addr}/");
    println!("  假接收器       : {}/recv/<token>", built.receiver.url_base);
    println!("  SQLite         : {}", args.db);
    println!("按 Ctrl-C 退出。");

    park();
    Ok(())
}

#[cfg(not(target_family = "unix"))]
fn park() {
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(target_family = "unix")]
fn park() {
    extern "C" fn handler(_sig: i32) {
        std::process::exit(0);
    }
    unsafe {
        libc_signal(15, handler); // SIGTERM
        libc_signal(2, handler);  // SIGINT
    }
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(target_family = "unix")]
unsafe fn libc_signal(sig: i32, handler: extern "C" fn(i32)) {
    // Avoid a libc dependency: use the libc `signal` symbol directly.
    #[link(name = "c")]
    extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }
    let _ = signal(sig, handler);
}
