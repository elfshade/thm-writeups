# TryHackMe — pwn101

**Room:** https://tryhackme.com/room/pwn101
**Category:** Binary Exploitation
**Difficulty:** Easy → Medium
**Date:** 2026-11-06
**Tools:** `file`, `checksec`, `strings`, IDA Pro, gdb + pwndbg, pwntools

A series of 9 binary exploitation challenges (pwn101 → pwn109), each in its own
subfolder with a writeup and exploit script.

| # | Challenge | Technique | Status |
|---|---|---|---|
| 1 | [pwn101](pwn101/README.md) | Stack Variable Overwrite | Done |
| 2 | [pwn102](pwn102/README.md) | Multi-Variable Overwrite | Done |
| 3 | [pwn103](pwn103/README.md) | ret2win & 16-byte Stack Alignment | Done |
| 4 | [pwn104](pwn104/README.md) | Stack Buffer Overflow & Shellcode on Executable Stack (NX Disabled) | Done |
| 5 | [pwn105](pwn105/README.md) | Signed 32-bit Integer Overflow to Spawn Shell | Done |
| 6 | [pwn106](pwn106/README.md) | Format String Stack Memory Disclosure & Endian Reversal | Done |
| 7 | [pwn107](pwn107/README.md) | Format String Canary/PIE Leak & Stack Buffer Overflow (ret2win) | Done |
| 8 | [pwn108](pwn108/README.md) | <!-- --> | WIP |
| 9 | [pwn109](pwn109/README.md) | <!-- --> | WIP |

Flags and room answers are redacted on purpose.
