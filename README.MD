# OPN-RE
## What is opn-re tool or ORV?

First of all, the idea of this tool is to find an open redirect vulnerability in a URL, either from a simple query parameter checker or from grabbing endpoints from Web Archieve, and test them all!
![Opn-Re](https://github.com/AAVision/opn-re/blob/da8ab89853889485e3d590d3bdbeaf82c9d31361/images/opn-re.png)

## Introduction
### What is open redirect vulernability?
An open redirect vulnerability entails an attacker manipulating the user and redirecting them from one site to another, which may be malicious. The cybersecurity community doesn’t put enough emphasis on open redirect vulnerabilities because they are considered a simple flaw commonly connected to phishing scams and social engineering.

However, open redirect vulnerabilities can help attackers in ways that go far beyond phishing. The true risk of this vulnerability is when it is utilized and combined with Server Side Request Forgery, XSS-Auditor bypass, Oauth Flaw, and so on.
---
![Opn-Re-Example](https://github.com/AAVision/opn-re/blob/da8ab89853889485e3d590d3bdbeaf82c9d31361/images/open-redirect-example.png)
## General
### How to Use this tool?
First of all, you can create a simple PHP script that redirects by passing the url in the url parameters in the URL, e.g.

```php
<?php

if($_GET["url"]){
    $url = $_GET["url"];
    header("Location: " .$url);
    die();
}

?>
```
Save this script on your XAMPP server and check if it will redirect to the URL provided in the parameters, e.g., `http://localhost/opn-re/?url=https://www.google.com`.

## Usage
```bash
go run . --help                                       
Usage: opn-re.exe [--domain DOMAIN] [--force] [--xss] [--simple] [--input INPUT] [--verbose]

Options:
  --domain DOMAIN, -d DOMAIN
  --force, -f
  --xss, -x
  --simple, -s
  --input INPUT, -i INPUT
  --verbose, -v
  --help, -h             display this help and exit
```
**Parameters:**
- d (-d or --domain): is the domain that the tool will scan: `google.com`.
- s (-s or --simple): this key will make a simple scan by embedding the parameter added in the `config.txt` file.
- f (-f or --force): this key will force to get all archieved urls.
- i (-i or --input): This key will take the name of the file that contains urls and add its parameters.
- v (-v or --verbose): This key will show all the processes and the urls scanned.
- x (-x or -xss): this key will search for xss injection in the query params.
- h (-h or --help): this key will display the help menu.

```bash
go run . --input test.txt

go run . --domain google.com --force

go run . --domain localhost/opn-re/ --simple --verbose
```

```bash
go run . --domain localhost/opn-re/ --simple
Scanning: http://localhost/opn-re/?url=https://www.google.com/
Scanning: http://localhost/opn-re/?file=https://www.google.com/
Scanning: http://localhost/opn-re/?l=https://www.google.com/
Scanning: http://localhost/opn-re/?ret=https://www.google.com/
Scanning: http://localhost/opn-re/?red=https://www.google.com/
Scanning: http://localhost/opn-re/?page=https://www.google.com/
Scanning: http://localhost/opn-re/?q=https://www.google.com/
Scanning: http://localhost/opn-re/?img=https://www.google.com/
Scanning: http://localhost/opn-re/?path=https://www.google.com/
Scanning: http://localhost/opn-re/?file=https://www.google.com/
Scanning: http://localhost/opn-re/?old=https://www.google.com/
Scanning: http://localhost/opn-re/?back=https://www.google.com/
Scanning: http://localhost/opn-re/?redirectBack=https://www.google.com/
Scanning: http://localhost/opn-re/?aspxerrorpath=https://www.google.com/
Scanning: http://localhost/opn-re/?u=https://www.google.com/
Scanning: http://localhost/opn-re/?langTo=https://www.google.com/
Scanning: http://localhost/opn-re/?redirect=https://www.google.com/
Scanning: http://localhost/opn-re/?From=https://www.google.com/
Scanning: http://localhost/opn-re/?Goto=https://www.google.com/
Scanning: http://localhost/opn-re/?end_display=https://www.google.com/
Scanning: http://localhost/opn-re/?AuthState=https://www.google.com/
Scanning: http://localhost/opn-re/?forward=https://www.google.com/
Scanning: http://localhost/opn-re/?redir=https://www.google.com/
Scanning: http://localhost/opn-re/?page=https://www.google.com/
Scanning: http://localhost/opn-re/?r=https://www.google.com/
Scanning: http://localhost/opn-re/?return_url=https://www.google.com/
Scanning: http://localhost/opn-re/?image_path=https://www.google.com/
Scanning: http://localhost/opn-re/?URL=https://www.google.com/
Scanning: http://localhost/opn-re/?location=https://www.google.com/
Scanning: http://localhost/opn-re/?toredirect=https://www.google.com/
Scanning: http://localhost/opn-re/?returnUrl=https://www.google.com/
Scanning: http://localhost/opn-re/?redirect_url=https://www.google.com/
Scanning: http://localhost/opn-re/?Next=https://www.google.com/
Scanning: http://localhost/opn-re/?ReturnUrl=https://www.google.com/
Scanning: http://localhost/opn-re/?uri=https://www.google.com/
Scanning: http://localhost/opn-re/?open=https://www.google.com/
Scanning: http://localhost/opn-re/?newurl=https://www.google.com/
Scanning: http://localhost/opn-re/?Referer=https://www.google.com/
Scanning: http://localhost/opn-re/?ActionCodeURL=https://www.google.com/
Scanning: http://localhost/opn-re/?link=https://www.google.com/
Scanning: http://localhost/opn-re/?r2=https://www.google.com/
The vulnerable urls are:  [http://localhost/opn-re/?url=https://www.google.com/]
Finished in: 740.6005ms
```

## LICENSE

This project is licensed under the MIT License. See the [LICENSE](https://github.com/aavision/opn-re/blob/main/LICENSE) file for details.

