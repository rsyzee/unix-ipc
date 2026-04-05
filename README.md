# unix-ipc
A lightweight Interprocess Communication (IPC) library using AF_UNIX sockets for efficient data exchange between processes.

# Behavior
- Simple and minimal protocol header
- Blocking I/O (waits until full message is received)
- CRC32 checksum for payload integrity
- Optimized CRC32 using hardware intrinsics


# Build & Run
```sh
git clone https://github.com/ryszee/unix-ipc.git
cd unix-ipc
mkdir build
cd build
cmake ..
make -j4
```
# Usage
Run as server :
```sh
./ipc-x -s
```
Run as client :
```sh
./ipc-x -c
```

# License
GPL-2.0
