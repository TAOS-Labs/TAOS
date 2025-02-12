# TAOS - Totally Awesome Operating System

Is a distributed operating system designed by University of Texas Austin Computer Science students as a project for CS 378: Multicore Operating Systems. Designed for x86 architecture this system is designed to support processes spawning processes on linked remote hosts running TAOS. The system abstracts the distributed nature of the processes from the end-user without requiring any action on their part. To this end TAOS will automatically handle the distribution of memory and the filesystem, while also deciding when to route IPC to a remote host. 

For a more detailed analysis and technical specifications, see [this repository's wiki](https://github.com/pgosar/TAOS/wiki). For more details regarding the implementation timeline, see [this repositories project page](https://github.com/pgosar/TAOS/projects).

## Dependencies
- Qemu (specifically version 9.2)
- [Limage](https://github.com/Amerikranian/limage). Note that this is not the version on crates.io, and so you'll likely have to [install the modified crate from git](https://doc.rust-lang.org/cargo/commands/cargo-install.html)

Compilation has been tested with WSL, Linux, and Mac. We provide no guarantees that this compiles on windows.

## Running
- To run in GUI mode: make run
- To run in terminal mode: make run-term
- To run tests: make test
- To ensure compliance with clippy and formatting: make check
- To format: make fmt