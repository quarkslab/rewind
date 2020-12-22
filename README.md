# README

This tool is a PoC for a snapshot-based coverage-guided fuzzer targeting Windows kernel components.

The idea is to clone the state of a running kernel (cpu and memory) into an Hyper-V partition to execute a specific function.
A targeted small virtual machine is obtained by mapping the requested code and data needed to run this function. The state is read from a snapshot obtained from a kernel debugger.
This small VM is then used to perform various tasks useful for a vulnerability researcher like getting an execution trace for the targeted function or fuzzing user-controlled inputs.

It leverages WHVP (Windows Hypervisor Platform) API to provide access to a Hyper-V partition.
See https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform for more details.

## Installation

WHVP (Windows Hypervisor Platform) must be enabled.

In a elevated powershell session, use the following command to check if WHVP is enabled:

```
Get-WindowsOptionalFeature -FeatureName HypervisorPlatform -Online

FeatureName      : HypervisorPlatform
DisplayName      : Windows Hypervisor Platform
Description      : Enables virtualization software to run on the Windows hypervisor
RestartRequired  : Possible
State            : Enabled
CustomProperties :
```

### Python wheel

A python wheel is provided in the releases section.
So the installation is quite straightforward:

```
# create a python virtual env (not mandatory)

$ py -m venv venv
$ .\venv\Scripts\activate

# install wheel with pip

$ pip install whvp_py-0.1.0-cp37-none-win_amd64.whl
```

### Source

If you prefer to build from source, you need to proceed as follows.

First you need to install LLVM and set the `LIBCLANG_PATH` environment variable (required by `bindgen`)
See https://rust-lang.github.io/rust-bindgen/requirements.html for a detailed explanation.

```
$ $env:LIBCLANG_PATH="C:\Program Files\LLVM\bin"
```

Then create a python virtual env:

```
$ py -m venv venv
$ .\venv\Scripts\activate
```

Go to the `whvp-py` directory:

```
$ cd whvp/whvp-py
```

Install requirements:

```
$ pip install -r requirements.txt
```

Then with `maturin` you can either build locally with:

```
$ maturin develop
```

Or build Python wheels for easy installation

```
$ maturin build --release
```

Some tests are provided and can be run with `pytest`:

```
$ pytest -v tests
```

## Usage

Two types of snapshots are supported. Both leverage pykd to access the state of Windbg.
The first type of snapshot use `rpyc` and `pykd` to provide an access to a live Windbg instance.
To use it you need to launch the `pykd_rpyc_server.py` script in your Windbg instance.

```
kd> !load pykd
kd> !py -3 -g [path]\pykd_rpyc_server.py
running rpyc server
```

The second type of snapshot use also `pykd` to make dump a valid context from a Windbg instance.
To use it you need to launch the `pykd_dump_context.py` script in your Windbg instance.

```
kd> !load pykd
kd> !py -3 -g [path]\pykd_dump_context.py [directory]
[go make a coffee, it can take a while]
```

The first type of snapshot is more adapted for a dynamic approach (when you are searching for a potential function to fuzz).
Once you find a potential candidate, use the second snapshot to make a dump. You will be able to use your debugger for another task.

A snapshot consists of 3 files:

- `context.json`: initial cpu state
- `params.json`: tracer parameters (expected return address, excluded addresses)
- `mem.dmp`: Windbg dump file

3 tools are provided.

The first one is a tracer `whvp-tracer` (located in `whvp/whvp-py/scripts/tracer.py`)

```
Usage: tracer.py [OPTIONS]

Options:
  --snapshot TEXT             [default: localhost:18861]
  --coverage [no|hit|instrs]  [default: no]
  --save-context              [default: False]
  --save-instructions         [default: False]
  --save-trace TEXT
  --replay TEXT
  --help                      Show this message and exit.
```

Its goal is to execute a target function in a Hyper-V partition and save an execution trace if needed.

You have several possibilities for obtaining the coverage:

- `no`: no coverage is used, the function is executed until the processor hits the expected return address
- `hit`: when pages containing code are mapped in the Hyper-V partition, instructions are replaced with software breakpoints and will be restored when they are executed for the first time. As a result you'll have the coverage on unique addresses.
- `instrs`: TF (Trap Flag) is enabled in `rflags` and each instruction will trigger an interruption from the virtual processor. As a result you'll have a full coverage of every instructions executed.

The trace can be saved into a `json` file for further processing or analysis.
You can choose to record only the encountered addresses or the full processor context.
You can also replay a specific input (for example found by the fuzzer).

```
$ python .\whvp\scripts\tracer.py --coverage instrs
2020-05-20 16:36:33,964 INFO  [whvp] running tracer
2020-05-20 16:36:34,319 INFO  [whvp_core::trace] setting bp on excluded address nt!KeBugCheck (fffff8076926a880)
2020-05-20 16:36:34,320 INFO  [whvp_core::trace] setting bp on excluded address nt!KeBugCheckEx (fffff8076926a8a0)
2020-05-20 16:36:35,423 INFO  [whvp] executed 37261 instruction(s), 18172 were unique in 1.4070376s (Success)
2020-05-20 16:36:35,426 INFO  [whvp] 132 page(s) were modified
2020-05-20 16:36:35,432 DEBUG [whvp_core::mem] destructing allocator
2020-05-20 16:36:35,434 DEBUG [whvp_core::whvp] destructing partition
```

The second one is the fuzzer `whvp-fuzzer` (located in `whvp/whvp-py/scripts/fuzzer.py`)

```
Usage: fuzzer.py [OPTIONS] [CONTEXT]

Options:
  --snapshot TEXT             [default: localhost:18861]
  --coverage [no|hit|instrs]  [default: hit]
  --max-time INTEGER          [default: 0]
  --max-iterations INTEGER    [default: 0]
  --display-delay INTEGER     [default: 1]
  --stop-on-crash             [default: False]
  --input TEXT                [required]
  --input-size TEXT           [required]
  --workdir TEXT              [required]
  --resume TEXT
  --help                      Show this message and exit.
```

The purpose of the script is to fuzz a target function by applying mutations on an input buffer.

```
$ python .\whvp\scripts\fuzzer.py --snapshot [path] --max-time 10 --input 0xffffcb8c1e3059a8 --input-size 0x40 --workdir .\fuzz
2020-05-20 16:39:13,172 INFO  [whvp] loading dump
2020-05-20 16:39:14,949 INFO  [whvp] fuzzer workdir is ..\tmp\fuzz\a6159ce2-d3d5-417f-8bfe-bfb1b042c261
2020-05-20 16:39:14,952 INFO  [whvp_core::fuzz] loaded 0 file(s) to corpus
2020-05-20 16:39:14,952 INFO  [whvp_core::fuzz] first execution to map memory
2020-05-20 16:39:15,079 INFO  [whvp_core::fuzz] reading input
2020-05-20 16:39:15,080 INFO  [whvp_core::fuzz] add first trace to corpus
2020-05-20 16:39:15,085 INFO  [whvp_core::fuzz] discovered 2245 new address(es), adding file to corpus
2020-05-20 16:39:15,086 INFO  [whvp_core::fuzz] start fuzzing
2020-05-20 16:39:15,090 INFO  [whvp_core::fuzz] discovered 51 new address(es), adding file to corpus
2020-05-20 16:39:15,093 INFO  [whvp_core::fuzz] discovered 8 new address(es), adding file to corpus
2020-05-20 16:39:15,097 INFO  [whvp_core::fuzz] discovered 8 new address(es), adding file to corpus
2020-05-20 16:39:15,102 INFO  [whvp_core::fuzz] discovered 6 new address(es), adding file to corpus
2020-05-20 16:39:15,104 INFO  [whvp_core::fuzz] discovered 3 new address(es), adding file to corpus
2020-05-20 16:39:15,121 INFO  [whvp_core::fuzz] discovered 2 new address(es), adding file to corpus
2020-05-20 16:39:15,123 INFO  [whvp_core::fuzz] discovered 2 new address(es), adding file to corpus
2020-05-20 16:39:15,190 INFO  [whvp_core::fuzz] discovered 2 new address(es), adding file to corpus
2020-05-20 16:39:15,509 INFO  [whvp_core::fuzz] discovered 426 new address(es), adding file to corpus
2020-05-20 16:39:15,510 INFO  [whvp_core::fuzz] got abnormal exit, saving input to "..\\tmp\\fuzz\\a6159ce2-d3d5-417f-8bfe-bfb1b042c261\\crashes\\687aab7cdb9415f2.bin"
2020-05-20 16:39:15,952 INFO  [whvp_core::fuzz] 1082 executions, 1082 exec/s, coverage 2753, new 508, code 143.36 kB, data 270.34 kB, corpus 7, crashes 1
[snip]
2020-05-20 16:39:23,962 INFO  [whvp_core::fuzz] 10808 executions, 1201 exec/s, coverage 2767, new 0, code 143.36 kB, data 270.34 kB, corpus 9, crashes 41
2020-05-20 16:39:24,616 INFO  [whvp_core::fuzz] got abnormal exit, saving input to "..\\tmp\\fuzz\\a6159ce2-d3d5-417f-8bfe-bfb1b042c261\\crashes\\45d0b5f9c92b4e69.bin"
2020-05-20 16:39:24,789 INFO  [whvp_core::fuzz] got abnormal exit, saving input to "..\\tmp\\fuzz\\a6159ce2-d3d5-417f-8bfe-bfb1b042c261\\crashes\\b816dfa892108baf.bin"
2020-05-20 16:39:24,952 INFO  [whvp_core::fuzz] fuzzing session ended after 10.0006871s and 12053 iteration(s)
2020-05-20 16:39:24,954 DEBUG [whvp_core::mem] destructing allocator
2020-05-20 16:39:24,955 DEBUG [whvp_core::whvp] destructing partition
```

The last one is a triager `whvp-triage` (located in `whvp/whvp-py/scripts/triage.py`)

```
Usage: triage.py [OPTIONS] CRASHES OUTPUT

Options:
  --snapshot TEXT  [default: localhost:18861]
  --limit INTEGER
  --help           Show this message and exit.
```

Its purpose is to triage the crashes obtained by the fuzzer.
It works by replaying crashing inputs and comparing the last executed instructions (by using the `limit` parameter)

```
$ python .\whvp\scripts\triage.py --snapshot [path] .\fuzz\7ea6bb7e-167e-4ca0-9287-0670331881d2\crashes\ .\triage
2020-05-20 16:44:01,077 INFO  [whvp] loading dump
2020-05-20 16:44:02,896 INFO  [whvp] loaded 64 crash(es)
2020-05-20 16:44:02,896 INFO  [whvp] gathering coverage
2020-05-20 16:44:02,897 INFO  [whvp] coverage exists for 14ad693179e1d296.bin, loading from file
2020-05-20 16:44:02,953 INFO  [whvp] coverage exists for 1713963ad35a010b.bin, loading from file
2020-05-20 16:44:03,001 INFO  [whvp] coverage exists for 17e89b73dbde7cdb.bin, loading from file
2020-05-20 16:44:03,069 INFO  [whvp] coverage exists for 1bd8594ab1972c6e.bin, loading from file
[snip]
2020-05-20 16:44:07,028 INFO  [whvp] triaged 64 crash(es)
2020-05-20 16:44:07,029 INFO  [whvp] found 2 unique crash(es)
2020-05-20 16:44:07,029 INFO  [whvp] 14ad693179e1d296.bin has 53 duplicate(s)
2020-05-20 16:44:07,186 INFO  [whvp] 3a85c8f8773d0ac9.bin has 8 duplicate(s)
2020-05-20 16:44:07,204 DEBUG [whvp_core::mem] destructing allocator
2020-05-20 16:44:07,204 DEBUG [whvp_core::whvp] destructing partition
```

## Known Bugs/Limitations

- This software is in a very early stage of development and an ongoing experiment.
- Sometimes the tracer is unable to trace the target function (most common issue is invalid virtual cpu state).
- When using `hit` coverage mode, the tracer will misbehave on some functions (it is the case with some switch tables). The reason is that each byte is replaced by software breakpoints (including data if they are present in a executable page).
- The target function will be executed with a unique virtual processor, you have no support for hardware or OS interrupts. As a result, it will not be interrupted (so no support for asynchronous code).
- This tool is best used for targetting small synchronous functions.
- To have best performances, minimize VM exits and modified pages because they can be really costly and will increase the time needed to execute the function. 

## License

This tool is currently developed and sponsored by Quarkslab under the Apache 2.0 license.

## Greetz

Hail to @yrp604, @0vercl0k, Alexandre Gazet for their help, feedbacks and thoughts. Thanks also to all my colleagues at Quarkslab!
