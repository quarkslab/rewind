
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

## rewind-bochs

- [ ] use bochscpu master
- [ ] improve mem accesses handling

## rewind-cli

- [ ] improve cli documentation
- [X] remove whvp backend for linux build
- [ ] add a snapshot subcommand
- [ ] need a dry-run parameter to measure fuzzing speed (no mutation will be performed)

## rewind-core


## rewind-system

- [ ] remove deku and use zerocopy instead

## rewind-snapshot

- [ ] improve parsing
- [X] add support for full dump
- [ ] improve file-based snapshot
