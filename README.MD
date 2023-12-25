# OPN-RE
## What is opn-re tool or ORV?

First of all, the idea of this tool is to find an open redirect vulnerability in a URL, either from a simple query parameter checker or from grabbing endpoints from Web Archieve, and test them all!
![Opn-Re](https://github.com/AAVision/opn-re/blob/da8ab89853889485e3d590d3bdbeaf82c9d31361/images/opn-re.png)

## Introduction
### What is open redirect vulernability?
An open redirect vulnerability entails an attacker manipulating the user and redirecting them from one site to another, which may be malicious. The cybersecurity community doesn’t put enough emphasis on open redirect vulnerabilities because they are considered a simple flaw commonly connected to phishing scams and social engineering.

However, open redirect vulnerabilities can help attackers in ways that go far beyond phishing. The true risk of this vulnerability is when it is utilized and combined with Server Side Request Forgery, XSS-Auditor bypass, Oauth Flaw, and so on.
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
Usage: opn-re.exe [--domain DOMAIN] [--force] [--xss] [--simple] [--input INPUT]

Options:
  --domain DOMAIN, -d DOMAIN
  --force, -f
  --xss, -x
  --simple, -s
  --input INPUT, -i INPUT
  --help, -h             display this help and exit
```
