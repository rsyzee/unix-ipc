# unix-ipc
Is a Interprocess Communication (IPC) using AF_UNIX socket. used to communicate and sharing data between processes
# Installation & run
```sh
git clone https://github.com/ryszee/unix-ipc.git
cd unix-ipc
mkdir build
cd build
cmake ..
make -j4 
```

# IPC Behaviour
-> Using simple custom protocol header
-> Block I/O until message fully received
-> Message payload checksum using CRC32
-> Fastly Calculate CRC32 using NEON/ARM Intrinsics

run as server :
```sh
./ipc-server -x
```
run as client :
```sh
./ipc-server
```

# License
GPL-2.0
