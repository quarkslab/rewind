
# TODO

- [ ] clean dependency tree with cargo tree
- [ ] setup cargo release
- [ ] improve tests
- [ ] add doc
- [ ] get test coverage
- [ ] update README
- [X] docker pipeline
- [ ] gitlab-ci pipeline for doc and tests (automatize bochscpu installation)
- [ ] use cargo make ?
- [ ] detect when hardware access is made
- [ ] kvm backend
- [ ] provide a basic driver loader
- [ ] fix symbol resolving
- [ ] improve coverage (need a way to have function size)
- [ ] improve error reporting
- [ ] use some kind of DSL to drive tracer
- [ ] split Tracer traits in sub-traits
- [ ] add a trait for Tracer to improve fuzzing loop (no need to have a full trace, just need a bitmap to update)


## rewind-bochs

- [X] use bochscpu master
- [ ] improve mem accesses handling
- [ ] use edge coverage

## rewind-whvp

- [ ] update to newest SDK (compilation error for now)
- [ ] improve breakpoint handling (need a MESOS file?)

## rewind-cli

- [ ] improve cli documentation
- [X] remove whvp backend for linux build
- [ ] add a snapshot subcommand
- [ ] need a dry-run parameter to measure fuzzing speed (no mutation will be performed)

## rewind-core

- [ ] improve fuzzing loop (trace is destroyed for every testcase, maybe use a bitmap)

## rewind-system

- [ ] remove deku and use zerocopy instead

## rewind-snapshot

- [ ] improve parsing (need to be more robust)
- [X] add support for full dump
- [X] improve file-based snapshot
