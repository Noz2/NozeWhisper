## NozeWhisper
An offline recon co-pilot that reads your scan output and tells you your next move.


# NozeWhisper

**It whispers, you strike.**

NozeWhisper is an offline recon co-pilot for pentesters and CTF players.
You paste the output of your recon tools, and it tells you what to try
next — and flags what you skipped. It advises; you hack.


## What it reads
- nmap (matches by service name, so non-default ports work too)
- gobuster / ffuf / feroxbuster / dirb
- nikto
- whatweb

## Why it's useful
- ~45 services and ~150 ports in the rulebook
- Web path hints (/.git, /uploads, /admin, and more)
- Uses modern tools (netexec, enum4linux-ng, feroxbuster)
- The rulebook is plain text — grow it with your own tricks

## Usage
```bash
python3 nozewhisper.py scan.txt        # auto-detects the tool
nmap -sV IP | python3 nozewhisper.py - # pipe straight in
```
