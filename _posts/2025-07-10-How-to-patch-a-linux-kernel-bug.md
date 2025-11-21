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
- Knowing who to CC is also important, you can use `./scripts/get_maintainer.pl <Modified File>` to get the maintainers.
- Attach the selftest result showing that the change passed the basical test
- In the talk, always use mutt to reply (Gmail’s plaintext mode sometimes doesn’t work well).


# 📑 Self-Test Example for sched

Considering it may require other qdiscs/classifier/actions so we just include them all

```config
scripts/config --enable CONFIG_NET_SCHED
scripts/config --enable CONFIG_NET_SCH_HTB
scripts/config --enable CONFIG_NET_SCH_HFSC
scripts/config --enable CONFIG_NET_SCH_PRIO
scripts/config --enable CONFIG_NET_SCH_QFQ
scripts/config --enable CONFIG_NET_SCH_SFQ
scripts/config --enable CONFIG_NET_SCH_FQ
scripts/config --enable CONFIG_NET_SCH_FQ_CODEL
scripts/config --enable CONFIG_NET_SCH_CODEL
scripts/config --enable CONFIG_NET_SCH_INGRESS
scripts/config --enable CONFIG_NET_SCH_NETEM
scripts/config --enable CONFIG_NET_SCH_DRR
scripts/config --enable CONFIG_NET_SCH_TBF
scripts/config --enable CONFIG_NET_SCH_MQPRIO
scripts/config --enable CONFIG_VETH
scripts/config --enable CONFIG_DUMMY
scripts/config --enable CONFIG_NET_CLS
scripts/config --enable CONFIG_NET_CLS_ACT
scripts/config --enable CONFIG_NET_CLS_BPF
scripts/config --enable CONFIG_NET_CLS_BASIC
scripts/config --enable CONFIG_NET_CLS_ROUTE4
scripts/config --enable CONFIG_NET_CLS_FW
scripts/config --enable CONFIG_NET_CLS_U32
scripts/config --enable CONFIG_NET_CLS_FLOW
scripts/config --enable CONFIG_NET_CLS_CGROUP
scripts/config --enable CONFIG_NET_CLS_FLOWER
scripts/config --enable CONFIG_NET_CLS_MATCHALL
```

Then we run the test
```sh
apt update -y && apt install -y python3-pip vim
pip3 install pyroute2 scapy==2.4.2 --break
python3 /tc-tests/tdc.py -v -f /tc-tests/qdiscs/cake.json
```