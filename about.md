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

I am Xiang Mei, a Ph.D. student at Arizona State University, working with [Dr. Yan Shoshitaishvili][17] (advisor), [Dr. Ruoyu (Fish) Wang][18], [Dr. Adam Doupé][19], and [Dr. Tiffany Bao][20] in the [SEFCOM lab][16]. My research primarily revolves around automated binary analysis, vulnerability discovery, and exploitation. Prior to my doctoral studies, I earned my Master’s degree from NYU in 2023, where I conducted research ([ARVO][22]) with [Dr. Brendan Dolan-Gavitt][15].


Since my sophomore year, I have been actively engaged in Capture The Flag (CTF) competitions. I compete as part of [Shellphish][12] and [r3kapig][13] teams under the handle n132, specializing in binary exploitation (PWN). Recently, I became the tenth person to solve all challenges on [Pwnable.tw][11], a journey that spanned seven years and built my exploitation skills. Moreover, I have been a [DEF CON CTF][10] finalist with team r3kapig since 2021. During my master's study at NYU, I served as the Lab Manager for [NYU Osiris Lab][9], organizing [CSAW-CTFs][8] in 2021 and 2022. I also participated in bug bounty programs to tackle real-world security challenges, such as the Linux kernel in Google's [kernelCTF][21] in 2025 and WYZE-V3 camera at [PWN2OWN Toronto][7] in 2023.


I am an advocate for open-source, contributing to major projects like the [Linux kernel][5] and [oss-fuzz][6]. I share various exploitation tools and techniques I develop on my [GitHub][4], including [Libc-GOT-Hijacking][1], [Dec-Safe-Linking][2], [BeapOverflow][3], and [more][4].

<style>
.cve-section { margin-top: 2rem; margin-bottom: 3rem; }
.cve-section h2 { margin-bottom: 0.75rem; }
.cve-group { margin-top: 1rem; }
.cve-group-label { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #666; margin-bottom: 0.5rem; }
.cve-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(185px, 1fr)); gap: 0.5rem; padding: 0; margin: 0; list-style: none; }
.cve-list a { display: block; text-align: center; padding: 0.35rem 0.6rem; font-size: 0.8rem; font-weight: 600; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #1a1a1a; border: 1.5px solid #1a1a1a; border-radius: 3px; text-decoration: none; transition: background 0.2s, color 0.2s; }
.cve-list a:hover { background: #1a1a1a; color: #fff; }
</style>

<div class="cve-section" markdown="0">
<h2>Community Contributions</h2>
<!--
  CVE ordering rule:
  - Only entries that have an assigned CVE number are listed (Discovered / Patched CVEs).
  - Sorted by CVE identifier in DESCENDING order: first by year (newest year first),
    then by sequence number within that year (highest number first).
    e.g. 2026 before 2025, and within 2026: 52942 > 52941 > ... > 22976.
  - Each entry links to the upstream fixing commit (git.kernel.org) for that CVE.
  - When adding a new CVE, insert it at the position its (year, number) dictates;
    do not append to the end.
-->
<div class="cve-group">
<div class="cve-group-label">Discovered / Patched CVEs</div>
<div class="cve-list">

  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=c3009418f9fa">🏔️ CVE-2026-53349</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=a84b6fedbc97078788be78dbdd7517d143ad1a77">🌊 CVE-2026-52942</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=7bf563badd37">🌲 CVE-2026-52941</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=7f2fcff15e99bb852f6967396ed12b38376e2c8d">🌷 CVE-2026-52940</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=34080db3e70ddf94c38512ad2331e3c3afca6cc1">🌅 CVE-2026-52939</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=375e4e33c18d">🍁 CVE-2026-52938</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=bddc09212c24">🌌 CVE-2026-52937</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=aa8963fdce667a42fb7f0bdd2909fadcab02f9a8">🏕️ CVE-2026-46322</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4feb1e20058e407cb00f45aff47f5b7e19a6bbf">🗻 CVE-2026-46321</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3bcf7aec6a9d16438f2cec29f5d7c8d5b8edf9b2">💧 CVE-2026-46320</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=aa6c6d9ee064aabfede4402fd1283424e649ca19">🌴 CVE-2026-45846</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=3d07ca5c0fae311226f737963984bd94bb159a87">🌻 CVE-2026-45845</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1e8e3f449b1e73b73a843257635b9c50f0cc0f0a">🌄 CVE-2026-45844</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=4c1367a2d7aad643a6f87c6931b13cc1a25e8ca7">🍂 CVE-2026-45843</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=e76607442d5b73e1ba6768f501ef815bb58c2c0e">🌠 CVE-2026-45842</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2195574dc6d9017d32ac346987e12659f931d932">🏜️ CVE-2026-45841</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=2091c6aa0df6aba47deb5c8ab232b1cb60af3519">🌋 CVE-2026-45840</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1c22483a2c4bbf747787f328392ca3e68619c4dc">🏖️ CVE-2026-45839</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=5828b9e5b272ecff7cf5d345128d3de7324117f7">🌵 CVE-2026-45838</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=4fddde2a732de60bb97e3307d4eb69ac5f1d2b74">🌸 CVE-2026-45837</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=9a91797e61d286805ae10a92cc48959c30800556">🌈 CVE-2026-43086</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1f3083aec8836213da441270cdb1ab612dd82cf4">🍃 CVE-2026-43085</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=605b52497bf89b3b154674deb135da98f916e390">⭐ CVE-2026-31546</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=52025ebaa29f4eb4ed8bf92ce83a68f24ab7fdf7">🏞️ CVE-2026-31428</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=6a2b724460cb67caed500c508c2ae5cf012e4db4">⛰️ CVE-2026-31427</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=f6484cadbcaf26b5844b51bd7307a663dda48ef6">🏝️ CVE-2026-31426</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=a54ecccfae62c5c85259ae5ea5d9c20009519049">🌿 CVE-2026-31425</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=3d5d488f11776738deab9da336038add95d342d1">🌼 CVE-2026-31424</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=4576100b8cd03118267513cafacde164b498b322">☀️ CVE-2026-31423</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1a280dd4bd1d616a01d6ffe0de284c907b555504">🌾 CVE-2026-31422</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=faeea8bbf6e958bf3c00cb08263109661975987c">🌟 CVE-2026-31421</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=fa6e24963342de4370e3a3c9af41e38277b74cf3">🌱 CVE-2026-31420</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=2884bf72fb8f03409e423397319205de48adca16">🪨 CVE-2026-31419</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=b3a6df291fecf5f8a308953b65ca72b7fc9e015d">🍀 CVE-2026-23439</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=614aefe56af8e13331e50220c936fc0689cf5675">🌺 CVE-2026-23398</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=dbdfaae9609629a9569362e3b8f33d0a20fd783c">🌙 CVE-2026-23397</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=c73bb9a2d33bf81f6eecaa0f474b6c6dbe9855bd">☘️ CVE-2026-23396</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0cc0c2e661af418bbf7074179ea5cfffc0a5c466">🪐 CVE-2026-23277</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6f1a9140ecda3baba3d945b9a6155af4268aafc4">🌬️ CVE-2026-23276</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=005671c60fcf1dbdb8bddf12a62568fd5e4ec391">❄️ CVE-2026-22977</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=0809c4bc06c9c961222df29f2eccfd449304056f">🔥 CVE-2026-22976</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=9fefc78f7f02d71810776fdeb119a05a946a27cc">🌪️ CVE-2025-68325</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=1bed56f089f09b465420bf23bb32985c305cfc28">🕳️ CVE-2025-40083</a>
  <a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=5e28d5a3f774f118896aec17a3a20a9c5c9dfc64">🗺️ CVE-2025-38477</a>
</div>
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
[22]: https://github.com/n132/ARVO/tree/main