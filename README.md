# Self_Deletion_BOF
BOF implementation of the research by @jonasLyk and the drafted PoC from @LloydLabs

## Why?
I didn't see that it currently existed (via the Community Kit) at the time of authorship.

## How do I run this?
1. In this case, you have two options:
	1. Use the existing, compiled object file, located in the `dist` directory (AKA proceed to major step two)
    2. Compile from source via the `Makefile`
        1. `cd src`
        2. `make clean`
        3. `make`
2. Load the `Aggressor` file, in the `Script Manager`, located in the `dist` directory
3. Within a provided `Beacon`, `beacon> self_delete`

## Any known downsides?
- We're still using the `Win32` API and `Dynamic Function Resolution`.  This is for you to determine as far as "risk".
  - Most of these calls can be replaced with `Nt` or `Zw` equivalents, which most (if not all) relevant stubs have been generated for you in the `syscalls.h` header file.
      - I **may** replace these with the aforementioned at a later point, but as it stands, I just wanted this up and "out there" for people first and foremost.
      - As it stands, there is one `64-bit` call to `NtClose`, if you wish, you may just create the `Dynamic Function Resolution` prototype in `win32_api.h` for `CloseHandle`.
