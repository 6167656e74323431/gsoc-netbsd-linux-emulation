# TODO

TODO: description

## Original Deliverables

| Goal | Status |
|-|-|
| Implement getrandom(2) | [Merged](https://github.com/NetBSD/src/commit/27c80d9318ef53cc2174ef8fc336fbc259961c12) |
| Implement waitid(2) | [Done](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/compare/f0258b8...waitid), not yet merged |
| Implement epoll\_create(2), epoll\_create1(2), epoll\_ctl(2), epoll\_wait(2), epoll\_pwait(2), epoll\_pwait2(2) | [Merged](https://github.com/NetBSD/src/commit/4fc9de10f24b099fc6a64d7b6efb3326bf58fbc5) and then [partially removed](https://github.com/NetBSD/src/commit/97dbe1c5fc7aa60f1c4c372c605a235f626a25a6) |
| Implement memfd\_create(2) | [Merged](https://github.com/NetBSD/src/commit/cb59abf3c3559fc4321683d63269288c48081e32) |
| Implement inotify\_init(2), inotify\_init1(2), inotify\_add\_watch(2), inotify\_rm\_watch(2) | [Done](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/compare/0f288b2...inotify), not yet merged |
| Implement readahead(2) | [Merged](https://github.com/NetBSD/src/commit/107c20d04c3c0fe3f929df71fc5bcab4ba19c266) |
| Implement newfstatat(2) | [Merged](https://github.com/NetBSD/src/commit/107c20d04c3c0fe3f929df71fc5bcab4ba19c266) |
| Implement statx(2) | [Merged](https://github.com/NetBSD/src/commit/107c20d04c3c0fe3f929df71fc5bcab4ba19c266) |
| Implement close\_range(2) | [Merged](https://github.com/NetBSD/src/commit/107c20d04c3c0fe3f929df71fc5bcab4ba19c266) |
| Implement ioprio\_set(2) | Not feasible, NetBSD does not have an I/O scheduler |
| Package the Linux Test Project | [Done](https://github.com/6167656e74323431/gsoc-netbsd-linux-emulation/compare/b56696d...pkgsrc), not yet merged |

## Extra Deliverables

| Goal | Status |
|-|-|
| Document system call versioning | [Merged](https://github.com/NetBSD/src/commit/c99712e08a47fec8aed5e9415d24f9dc0ab7d781) |
