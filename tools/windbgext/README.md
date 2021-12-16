# README

WinDbg extension to create snapshots to use with rewind.

## Installation

Use cargo

```
$ cargo build --release
```

Then copy ``windbgext.dll`` to WinDbg extensions directory (``C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext``)

## Usage

Load extension during a kernel debug session

```
kd> .load windbgext
```

Then use ``!snapshot``

```
kd> !snapshot c:\\Snapshots
Writing processor state to c:\Snapshots\19041.1.amd64fre.vb_release.191206-1406\nt!NtTraceControl\context.json
Writing parameters to c:\Snapshots\19041.1.amd64fre.vb_release.191206-1406\nt!NtTraceControl\params.json
Writing snapshot to c:\Snapshots\19041.1.amd64fre.vb_release.191206-1406\nt!NtTraceControl\mem.dmp
Creating c:\Snapshots\19041.1.amd64fre.vb_release.191206-1406\nt!NtTraceControl\mem.dmp - Active kernel and user memory bitmap dump
Collecting pages to write to the dump. This may take a while.
0% written.
5% written. 1 min 1 sec remaining.
10% written. 55 sec remaining.
15% written. 1 min 8 sec remaining.
20% written. 37 sec remaining.
25% written. 29 sec remaining.
30% written. 21 sec remaining.
35% written. 22 sec remaining.
40% written. 23 sec remaining.
45% written. 23 sec remaining.
50% written. 19 sec remaining.
55% written. 20 sec remaining.
60% written. 19 sec remaining.
65% written. 12 sec remaining.
70% written. 10 sec remaining.
75% written. 9 sec remaining.
80% written. 12 sec remaining.
85% written. 9 sec remaining.
90% written. 3 sec remaining.
95% written. 2 sec remaining.
Wrote 3.0 GB in 47 sec.
The average transfer rate was 63.5 MB/s.
Dump successfully written
```