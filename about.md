---
layout: about
title: about
permalink: /about
subtitle: 

profile:
  align: right
#   image: prof_pic.jpg
#   image_circular: false # crops the image to make it circular
#   more_info: >
    # <p>Ariona State University</p>
    # <p>Tempe, Arizona</p>

news: true # includes a list of news items
selected_papers: false # includes a list of papers marked as "selected={true}"
social: true # includes social icons at the bottom of the page
---

I am Xiang Mei, a Ph.D. student at Arizona State University, working with [Dr. Yan Shoshitaishvili][17] (advisor), [Dr. Ruoyu (Fish) Wang][18], [Dr. Adam Doupé][19], and [Dr. Tiffany Bao][20] in the [SEFCOM lab][16]. My research primarily revolves around automated binary analysis, vulnerability discovery, and exploitation. Prior to my doctoral studies, I earned my Master’s degree from NYU in 2023, where I conducted research (currently under submission) with [Dr. Brendan Dolan-Gavitt][15].


Since my sophomore year, I have been actively engaged in Capture The Flag (CTF) competitions. I compete as part of [Shellphish][12] and [r3kapig][13] teams under the handle n132, specializing in binary exploitation (PWN). Recently, I became the tenth person to solve all challenges on [Pwnable.tw][11], a journey that spanned seven years and built my exploitation skills. Moreover, I have been a [DEF CON CTF][10] finalist with team r3kapig since 2021. During my master's study at NYU, I served as the Lab Manager for [NYU Osiris Lab][9], organizing [CSAW-CTFs][8] in 2021 and 2022. I also participated in bug bounty programs to tackle real-world security challenges, such as the Linux kernel in Google's [kernelCTF][21] in 2025 and WYZE-V3 camera at [PWN2OWN Toronto][7] in 2023.


I am an advocate for open-source, contributing to major projects like the [Linux kernel][5] and [oss-fuzz][6]. I share various exploitation tools and techniques I develop on my [GitHub][4], including [Libc-GOT-Hijacking][1], [Dec-Safe-Linking][2], [BeapOverflow][3], and [more][4].

<style>
.cve-section h1 { margin-bottom: 1rem; }
.cve-list { display: flex; flex-wrap: wrap; gap: 0.5rem; padding: 0; margin: 0; list-style: none; }
.cve-list a { display: inline-block; padding: 0.35rem 0.75rem; font-size: 0.85rem; font-weight: 600; font-family: monospace; color: #1a1a1a; border: 1.5px solid #1a1a1a; border-radius: 3px; text-decoration: none; transition: background 0.2s, color 0.2s; }
.cve-list a:hover { background: #1a1a1a; color: #fff; }
</style>

<div class="cve-section" markdown="0">
<h1>Discovered/Patched CVE</h1>
<div class="cve-list">
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0809c4bc06c9c961222df29f2eccfd449304056f">CVE-2026-22976</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=005671c60fcf1dbdb8bddf12a62568fd5e4ec391">CVE-2026-22977</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=fbe48f06e64134dfeafa89ad23387f66ebca3527">CVE-2025-38477</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1bed56f089f09b465420bf23bb32985c305cfc28">CVE-2025-40083</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0b6216f9b3d1c33c76f74511026e5de5385ee520">CVE-2025-68325</a>
</div>
</div>

[1]: https://github.com/n132/Libc-GOT-Hijacking
[2]: https://github.com/n132/Dec-Safe-Linking
[3]: https://github.com/n132/BeapOverflow
[4]: https://github.com/n132
[5]: https://www.kernel.org/
[6]: https://github.com/google/oss-fuzz
[7]: https://www.zerodayinitiative.com/blog
[8]: https://www.csaw.io/
[9]: https://osiris.cyber.nyu.edu/
[10]: https://defcon.org/
[11]: https://pwnable.tw/
[12]: https://shellphish.net/
[13]: https://r3kapig.com/
[15]: https://engineering.nyu.edu/faculty/brendan-dolan-gavitt
[16]: https://sefcom.asu.edu/
[17]: https://yancomm.net/
[18]: https://ruoyuwang.me/
[19]: https://adamdoupe.com/
[20]: https://www.tiffanybao.com/
[21]: https://google.github.io/security-research/kernelctf/rules.html