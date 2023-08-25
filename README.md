# GSoC 2023: NetBSD Linux System Call Emulation: "A Tale of Two Binaries"

NetBSD's Linux system call (syscall) emulation provides near seamless ability to run Linux binaries, but traditionally it has been hard to answer the question "will it work with program X?"
This Google Summer of Code Project aims to put a dent in that issue by taking a more systematic approach to syscall implementation by using real-world programs to gauge which syscalls are worth implementing, and not use them to decide when a syscall is done.
Additionally, a comprehensive test suite (the [Linux Test Project](https://linux-test-project.github.io/)) was ported and support was added to test emulation using NetBSD's test suite (ATF(7)).

A full diff of the changes to the main source tree can be found [here](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/compare/2f15c46...trunk), and a full diff of the main pkgsrc tree an be found [here](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/compare/b56696d...pkgsrc).

## Deliverables

The following table summarizes the status of the deliverables from the [original proposal](https://www.pta.gg/assets/pdf/gsoc-proposal.pdf) as of 25 August 2023.

| Deliverable | Status |
|-|-|
| Implement getrandom(2) | [Merged](https://github.com/NetBSD/src/commit/229b77042f914d6c0154fb10bfaba137ee2737b8) |
| Implement waitid(2) | [Merged](https://github.com/NetBSD/src/commit/69e4d6a089c3506cf5ce6b44a6275ff36faa3d63) |
| Implement epoll\_create(2), epoll\_create1(2), epoll\_ctl(2), epoll\_wait(2), epoll\_pwait(2), epoll\_pwait2(2) | [Merged](https://github.com/NetBSD/src/commit/d11110f47395fad20b98cd0acd8c15e342942014) ([also](https://github.com/NetBSD/src/commit/2c545067c78a4b84d16735051f9ff75bb33c88e8)) and then [partially removed](https://github.com/NetBSD/src/commit/e6ea8674241503ca267e91db470ee29fe4ae06f6) |
| Implement memfd\_create(2) | [Merged](https://github.com/NetBSD/src/commit/7eace3da0cd50687e03e36df30a9c0ede7f6bfe1) ([also](https://github.com/NetBSD/src/commit/d3ba7ba3a2e5f7545ce6475eec2b87d28dd9bfe4), [also](https://github.com/NetBSD/src/commit/4ab15e90fbc652f184b4b666ebb03155e350998d)) |
| Implement inotify\_init(2), inotify\_init1(2), inotify\_add\_watch(2), inotify\_rm\_watch(2) | [Merged](https://github.com/NetBSD/src/commit/8575c986c481647b7f22dad3ee667f50eaf55df9) ([also](https://github.com/NetBSD/src/commit/b7a2c5757f93ff98daa28e58c492788207b452cb), [also](https://github.com/NetBSD/src/commit/ed30ecde8c81e36f1ded305e04ea44118898d2e4), [also](https://github.com/NetBSD/src/commit/2915865e7d6b0827b7e94a15182426256c6c81dd)) |
| Implement readahead(2) | [Merged](https://github.com/NetBSD/src/commit/a0a4eb1d2ef812bd289da9273c2bd475b6f3e30c) |
| Implement newfstatat(2) | [Merged](https://github.com/NetBSD/src/commit/a0a4eb1d2ef812bd289da9273c2bd475b6f3e30c) |
| Implement statx(2) | [Merged](https://github.com/NetBSD/src/commit/a0a4eb1d2ef812bd289da9273c2bd475b6f3e30c) |
| Implement close\_range(2) | [Merged](https://github.com/NetBSD/src/commit/a0a4eb1d2ef812bd289da9273c2bd475b6f3e30c) |
| Implement ioprio\_set(2) | Not feasible |
| Package the Linux Test Project | [Done](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/compare/b56696d...pkgsrc), not yet merged |
| Document system call versioning (extra) | [Merged](https://github.com/NetBSD/src/commit/e706571b76f3970eefc2e8eec0c848baa6681988) ([rendered](https://man.netbsd.org/versioningsyscalls.9)) |
| Add support Linux emulation testing in ATF(7) (extra) | [Merged](https://github.com/NetBSD/src/commit/b7a2c5757f93ff98daa28e58c492788207b452cb) |

## Notes and Implementation Details

As expected, many of the implementation plans from the [original proposal](https://www.pta.gg/assets/pdf/gsoc-proposal.pdf) turned out to be flawed.
This section outlines how the syscalls were actually implemented, and some of the limitations of the implementations.

memfd\_create(2) was implemented directly in terms of uvm(9) operations, in particular the backing is provided by a uvm\_object created by uao\_create(9).
Since it was convenient, we also decided to make it a native NetBSD syscall.
As was [pointed out](https://mail-index.netbsd.org/tech-kern/2023/08/11/msg029092.html), the memfd\_create(2) does not currently have any limits that can be imposed from the outside.

The epoll\_\*(2) syscalls were implemented by directly porting FreeBSD's Linux compatibility version.
It is implemented as argument translation over kqueue(2)'s EVFILT\_READ and EVFILT\_WRITE, and so it necessitated versioning kqueue(2) to more closely match FreeBSD (hence why I also wrote a man page for syscall versioning).
Unfortunately this design suffers from the limitation that an epoll file descriptor under Linux emulation will not survive a fork(2).
After some [initial discussion](https://mail-index.netbsd.org/tech-kern/2023/06/21/msg028926.html) I decided to also add native NetBSD stubs to allow for better testing, but this [proved to be controversial](https://mail-index.netbsd.org/tech-userlevel/2023/07/31/msg014063.html).
Although despite this limitation, the epoll implementation is sufficient to allow a large swath of programs (ie. Go programs) to run.

The inotify\_\*(2) syscalls were also implemented in terms of kqueue(2).
The main challenge with inotify is that it preserves the exact ordering events, which kqueue(2) does not.
To accomplish this the implementation hooks into the event callbacks of kqueue(2), but uses its own queue.
Since kqueue(2) attaches to file descriptors, which are a scarce resource, there are some events which this implementation will not generate (reading from files inside a watched directory).
Additionally moves cannot always be correlated, so in some cases a rename may be reported as a delete and create, which is fine for its purpose as a compatibility shim.
Finally as a bit of a hack, some operations that could have gone through kevent1() to be done by hand because filterops::f\_touch could not be used due to the locking situation in the kqueue(2) subsystem (see [kqueue\_register](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/blob/trunk/sys/kern/kern_event.c#L1981)).

getrandom(2), waitid(2), readahead(2), and close\_range(2) have direct analogues in NetBSD, and so the implementation consists of translating arguments and calling the respective NetBSD functions.

statx(2) and newfstatat(2) already existed, statx(2) had a bug and newfstatat(2) already existed, but under the name fstatat64(2) (the name changes based on the Linux architecture, but the functionality is otherwise the same).
Besides fixing the bug, all that was necessary was to add the correct stubs to the relevant syscalls.master file.

NetBSD does not currently have an I/O scheduler and so ioprio\_set(2) could not be feasibly implemented given the amount of time available (adding an I/O scheduler is an entire project).

## What about the two binaries?

[Nebula](https://github.com/slackhq/nebula/) version 1.6.1 generally works, however the fact that TUN devices function differently on Linux limits its usefulness to just acting as a lighthouse and/or a relay.

[Syncthing](https://syncthing.net/) version 1.23.7 works, it can reliably sync files.
It does, however, emit a single warning on startup because of the non-existence of ioprio\_set(2).
