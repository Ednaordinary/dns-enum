# dns-enum

This script tries every permutation of A-Z and 0-9 through a DNS server. Please note the following limitations:

- Only A records are tried
- It is rather slow, even in rust, as the runtime increases times 37 for each character in the subdomain permutation. I have also only gotten up to 3.8 Gbps with 10 processes.
- The DNS server may at any time decide it is being attacked
- It requires at least 3 threads per process (this is not normally an issue)
- It does not exit after completing enumeration, and must be manually killed

This script is mainly for networks where subdomains do not has https or tls certificates that can be found from public ledgers.

Run:
```bash
cargo run -r 1 0 10
```

The first digit (1 here) - The amount of processes being spawned for the enumerator.
The second digit (0 here) - The offset of the process.
The third digit (10 here) - The length of the subdomains to try.

To run as a single process, the first two arguments should be 1 and 0. To run as multiple processes, first compile:
```bash
cargo build -r
mv ./target/release/dns-enum ./
```
Then a bash script such as this can be used to spawn multiple processes:
```bash
for ((i=0; i<=100; i++)); do
  ./dns-enum 100 $i 10 >> dns.txt &
done
```

This will spawn workers in the background, so to kill them do:
```bash
pkill -9 -i "dns-enum"
```
