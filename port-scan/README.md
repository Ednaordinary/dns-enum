# Port Scanner

This is a high rate port scanner. Please note the following limitations:

- It is built to scan a /16 subnet, as that is the net I was scanning at the time. Using a single process, it can also pretty easily scan a /24
- Scans ports 1-1000 on the full subnet in ~30 seconds with 2 Gibps of traffic and ~96 core machine. 36 minutes for all non-dynamic ports (1-49151)
- The network may at any time decide it is being attacked
- It requires at least 2 threads per process (this is not normally an issue)
- This can pretty easily overpower networks (not bandwidth wise but connection wise), as it spawns ~2184467 connections a second, depending on hardware.

Run:
```bash
cargo run -r 1
```

The first digit (1 here) - The third digit in the IP (i.e. specifying X will scan 0.0.X.0 through 0.0.X.256)

To specify the specific /16, edit the "0.0." on line 22 in main.rs

To run as multiple processes, first compile:
```bash
cargo build -r
mv ./target/release/meower ./
```
Then a bash script such as this can be used to spawn multiple processes:
```bash
for ((i=0; i<=255; i++)); do
	./meower1 $i | grep ":" | tee -a subnet.txt &
done
wait
```

This will spawn workers in the background, so to kill them before all hosts are scanned:
```bash
pkill -9 -i "meower"
```
