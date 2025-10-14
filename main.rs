use async_std::net::UdpSocket;
use radix_fmt::radix_36;
use rustdns::types::*;
use rustdns::Message;
use std::env;
use std::sync::Arc;
use tokio::task::JoinSet;

fn radix_change(n: u32) -> String {
    return radix_36(n).to_string();
}

async fn lookup(perm: u32, socket: Arc<UdpSocket>) -> Result<(), Box<dyn std::error::Error>> {
    let postfix = ".mines.edu";
    let host: String = vec![radix_change(perm), postfix.to_string()].join("");
    let mut mes = Message::default();
    mes.add_question(&host, Type::A, Class::Internet);
    let question = mes.to_vec()?;
    let _ = socket.send(&question).await;
    Ok(())
}

async fn socket_listener(
    domains: u32,
    socket: Arc<UdpSocket>,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..(domains - 1) {
        let mut resp = [0; 512];
        let len = socket.recv(&mut resp).await?;
        let answer = Message::from_slice(&resp[0..len])?;
        if answer.rcode == rustdns::Rcode::NoError {
            if answer.answers.len() == 0 {
                let answer_fmt = answer.to_string();
                let domain = answer_fmt.lines().nth(4).unwrap_or_default();
                println!("{}", domain);
            } else {
                println!("{}", answer.answers[0].name)
            }
        }
    }
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binding = vec!["0.0.0.0:", "0"];

    let socket = UdpSocket::bind(binding.concat()).await?;
    socket.connect("127.0.0.1:53").await?;
    let arc_socket = Arc::new(socket);
    let cloned_socket = Arc::clone(&arc_socket);
    let args: Vec<String> = env::args().collect();
    let sparsity = args[1].parse::<u8>().unwrap() as u32;
    let offset = args[2].parse::<u8>().unwrap() as u32;
    let domains: u32 = 36u32.pow(args[3].parse::<u32>().unwrap());
    let handle = tokio::spawn(async move {
        let _ = socket_listener(domains, cloned_socket).await;
    });
    let mut lookups = JoinSet::new();
    for i in 0..domains {
        if (i + offset) % sparsity != 0 {
            continue;
        } else if (i + offset) % (sparsity * 10_u32.pow(5)) != 0 {
            lookups.join_all().await;
            lookups = JoinSet::new();
        }
        // println!("- {}", i);
        let cloned_socket = Arc::clone(&arc_socket);
        lookups.spawn(async move {
            let _ = lookup(i, cloned_socket).await;
        });
        // println!("{:?}", radix_change(i));
    }
    // let _ = lookups.join_all().await;
    let _ = handle.await?;
    Ok(())
}
