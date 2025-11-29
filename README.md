# Linux-Rat-Scan

A rat scanner, search for malware, rootkits and viruses on a linux server

It installs scanners, and scans the server for linux rats.

**Scanners**

- clamav
- rkhunter
- chkrootkit
- lynis

**Installation**
In linux terminal: 

```cd ~```

```touch rat_scan.sh```

```nano rat_scan.sh```

Paste the .sh script

```Ctrl+O```

```Ctrl+Z```

```chmod u+x rat_scan.sh```

**Run rat scan**
```./rat_scan.sh```

Be mindful that Clamav takes a while to scan and can take up lots of server resources to do so. Clamav only runs at the end!

**Reports**

Reports are stored in:/var/security/ for each scanner.

