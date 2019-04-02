GoodbyeDPI — Passive Deep Packet Inspection blocker and Active DPI circumvention utility
=========================

This software designed to bypass Deep Packet Inspection systems found in many Internet Service Providers which block access to certain websites.

It handles DPI connected using optical splitter or port mirroring (**Passive DPI**) which do not block any data but just replying faster than requested destination, and **Active DPI** connected in sequence.

**Windows 7, 8, 8.1 and 10** with administrator privileges required.

# How to use

Download [latest version from Releases page](https://github.com/ValdikSS/GoodbyeDPI/releases) and run.

```
Usage: goodbyedpi.exe [OPTION...]
 -p          block passive DPI
 -r          replace Host with hoSt
 -s          remove space between host header and its value
 -m          mix Host header case (test.com -> tEsT.cOm)
 -f [value]  set HTTP fragmentation to value
 -k [value]  enable HTTP persistent (keep-alive) fragmentation and set it to value
 -n          do not wait for first segment ACK when -k is enabled
 -e [value]  set HTTPS fragmentation to value
 -a          additional space between Method and Request-URI (enables -s, may break sites)
 -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)
 --port        [value]    additional TCP port to perform fragmentation on (and HTTP tricks with -w)
 --ip-id       [value]    handle additional IP ID (decimal, drop redirects and TCP RSTs with this ID).
                          This option can be supplied multiple times.
 --dns-addr    [value]    redirect UDP DNS requests to the supplied IP address (experimental)
 --dns-port    [value]    redirect UDP DNS requests to the supplied port (53 by default)
 --dnsv6-addr  [value]    redirect UDPv6 DNS requests to the supplied IPv6 address (experimental)
 --dnsv6-port  [value]    redirect UDPv6 DNS requests to the supplied port (53 by default)
 --dns-verb               print verbose DNS redirection messages
 --blacklist   [txtfile]  perform HTTP tricks only to host names and subdomains from
                          supplied text file. This option can be supplied multiple times.

 -1          -p -r -s -f 2 -k 2 -n -e 2 (most compatible mode, default)
 -2          -p -r -s -f 2 -k 2 -n -e 40 (better speed for HTTPS yet still compatible)
 -3          -p -r -s -e 40 (better speed for HTTP and HTTPS)
 -4          -p -r -s (best speed)
```

To check if your ISP's DPI could be circumvented, run `3_all_dnsredir_hardcore.cmd` first. This is the most hardcore mode which will show if this program is suitable for your ISP and DPI vendor at all. If you can open blocked websites with this mode, it means your ISP has DPI which can be circumvented. This is the slowest and prone to break websites mode, but suitable for most DPI.

Try `goodbyedpi -1` to see if it works too.

Then try `goodbyedpi.exe -2`. It should be faster for HTTPS sites. Mode `-3` speed ups HTTP websites.

Use `goodbyedpi.exe -4` if it works for your ISP's DPI. This is the fastest mode but not compatible with every DPI.

# How does it work

### Passive DPI

Most Passive DPI send HTTP 302 Redirect if you try to access blocked website over HTTP and TCP Reset in case of HTTPS, faster than destination website. Packets sent by DPI usually have IP Identification field equal to `0x0000` or `0x0001`, as seen with Russian providers. These packets, if they redirect you to another website (censorship page), are blocked by GoodbyeDPI.

### Active DPI

Active DPI is more tricky to fool. Currently the software uses 6 methods to circumvent Active DPI:

* TCP-level fragmentation for first data packet
* TCP-level fragmentation for persistent (keep-alive) HTTP sessions
* Replacing `Host` header with `hoSt`
* Removing space between header name and value in `Host` header
* Adding additional space between HTTP Method (GET, POST etc) and URI
* Mixing case of Host header value

These methods should not break any website as they're fully compatible with TCP and HTTP standards, yet it's sufficient to prevent DPI data classification and to circumvent censorship. Additional space may break some websites, although it's acceptable by HTTP/1.1 specification (see 19.3 Tolerant Applications).

The program loads WinDivert driver which uses Windows Filtering Platform to set filters and redirect packets to the userspace. It's running as long as console window is visible and terminates when you close the window.

# How to build from source

This project can be build using **GNU Make** and [**mingw**](https://mingw-w64.org). The only dependency is [WinDivert](https://github.com/basil00/Divert).

To build x86 exe run:

`make CPREFIX=i686-w64-mingw32- WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/x86`

And for x86_64:

`make CPREFIX=x86_64-w64-mingw32- BIT64=1 WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/amd64`

# How to install as Windows Service

Use `service_install_russia_blacklist.cmd`, `service_install_russia_blacklist_dnsredir.cmd` and `service_remove.cmd` scripts.  
Modify them according to your own needs.

# Known issues

* Horribly outdated Windows 7 installations are not able to load WinDivert driver due to missing support for SHA256 digital signatures. Install KB3033929 [x86](https://www.microsoft.com/en-us/download/details.aspx?id=46078)/[x64](https://www.microsoft.com/en-us/download/details.aspx?id=46148), or better, update the whole system using Windows Update.
* Some SSL/TLS stacks unable to process fragmented ClientHello packets, and HTTPS websites won't open. Bug: [#4](https://github.com/ValdikSS/GoodbyeDPI/issues/4), [#64](https://github.com/ValdikSS/GoodbyeDPI/issues/64).
* ESET Antivirus is incompatible with WinDivert driver [#91](https://github.com/ValdikSS/GoodbyeDPI/issues/91). This is most probably antivirus bug, not WinDivert.


# Similar projects

- **[zapret](https://github.com/bol-van/zapret)** by @bol-van (for Linux).
- **[Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)** by @SadeghHayeri (for MacOS, Linux and Windows).

# Kudos

Thanks @basil00 for [WinDivert](https://github.com/basil00/Divert). That's the main part of this program.

Thanks for every [BlockCheck](https://github.com/ValdikSS/blockcheck) contributor. It would be impossible to understand DPI behaviour without this utility.
