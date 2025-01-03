---
layout: page
title: Kernel Archive
permalink: /archive
---

# Challenge List for Practicing

Feel free to practice by following the order (or any order).

- [2021 VULNCON - IPS](../2024/02/09/IPS.html): Heap Address Leaking cross kmem-cache
- [2021 VULNCON - IPS](../2024/02/28/IPS-Freelist.html): FreeList Hijacking
- [2021 VULNCON - IPS](../2024/02/29/IPS-Cross-Slab-Attack.html): Cross-Page Overwriting, Simple Page Level Heap Fengshui
- [2021 CorCTF - Wall of Perdition](../2024/05/27/Wall-of-Perdition.html): UAF2Leak, RetSpill, `FG-KASLR` bypassing
- [2024 DownUnderCTF - Faulty Kernel](../2024/07/18/Faulty-Kernel.html): Page Struct, `pipe_buffer`, Cross Cache, Data Follow attacking(`/etc/passwd`)
- [2024 CrewCTF - kUlele](../2024/08/14/kUlele.html): Cross Cache from Page allocation to Slub
- [2022 corCTF - Cache of Castaways](../2024/06/28/Castaways.html): Limit Heap Overflow, Limit Spray Fengshui Crafting, Cred Spray
- [2022 corCTF - Cache of Castaways](../2024/06/28/Castaways.html): `pipe_buffer` AAR/AAW
- [2022 CVE-2022-4543](https://github.com/n132/libx/blob/main/kaslr.c): Reliable Entry Bleeding
- [2023 corCTF - Sysruption](../2024/09/28/sysruption.html): `sysret`, `iret`, `tcp_prot`, and `micro-arch`.
- [2023 HITCON - Wall-Rose](../2024/09/29/rose.html): `pipe_buffer` AAR/AAW
- [2022 corCTF - CorJail](../2024/10/12/CorJail.html): `pipe_buffer` AAR/AAW, Docker Escaping

# Reproduced CVEs:

I reproduced these kernel CVEs but have not published write-ups:

- [KCTF - cve-2023-4623](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2023-4623_lts_cos/)
- [KCTF - cve-2023-31436](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2023-31436_mitigation/)


# Challenges without Write-Up

I solved these kernel challenges but have not published write-ups:

- [pwn.college - Kylebotfs](https://pwn.college/quarterly-quiz/kylebotfs/): Intro of Kernel Heap
- [pwn.college - Kernel Exploitation](https://pwn.college/software-exploitation/kernel-exploitation/): Intro of FBS 
- [2024 idekCTF- Dead Pwners Socity](https://github.com/idekctf/idekctf-2024/tree/main/pwn/dead-pwners-society): Race Condition, CFI, AAF, Fengshui, FUSE


# Obsolete

These challenges/skills are old/simple/obsolete. Practice if you like:

- [2021 QWB - notebook](../2022/05/20/Introduction-of-Kernel-Pwn-userfaultfd.html): Race Condition, `userfaultfd`
- [2021 asisCTF minimemo (Heap Overflow / Link Related Attack)][1]



[1]: https://github.com/n132/n132.github.io/blob/master/code/minimemo/README.md
