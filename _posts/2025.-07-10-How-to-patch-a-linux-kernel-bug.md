---
title: "How to patch a linux kernel bug"
date: 2025-07-10 15:13:47
tags: 
layout: post
---
<!---more-->

# 📑 CheckList
- Download the latest version of the linux kernel
- Make changes to the code
- Compile the code to make sure there is no compilation issue (warning/error), then do self-testing and make sure the original PoC doesn’t crash the vul. If possible, run a fuzzer to avoid potential issues.
- `git add` changed files
- `git commit` to add a commit message. `git commit —amend` can be used to change the commit information
- `git log -1 --pretty=%B > /tmp/msg.txt && fmt -w 72 /tmp/msg.txt > /tmp/newmsg.txt && git commit --amend -F /tmp/newmsg.txt`
- Use `git format-patch -1` to generate the patch or `git format-patch -v2 -1` to add version information
- `./scripts/checkpatch.pl --strict --codespell --show-types 0001-net-sched-sch_qfq-Fix-null-deref-in-agg_dequeue.patch`
- Ensure you have signed off tag (use your real name) and include a “Fixes” tag. If it’s not a bug you found, please use the “Reported-by” tag to give credit to the reporter.
-  Add a short version description, e.g., `v1: Add lock to avoid race in agg_xxx`
- Use git send-email to send the patch. DO NEVER use  `--in-reply-to=` . If it’s not the initial version, please add a link to quote the previous talk. 
- Knowing who to CC is also important
- In the talk, always use mutt to reply (Gmail’s plaintext mode sometimes doesn’t work well).