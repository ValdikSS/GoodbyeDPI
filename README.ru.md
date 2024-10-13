GoodbyeDPI — утилита для обхода систем Глубокой Проверки Пакетов (DPI)
=========================

Это программное обеспечение предназначено для обхода систем глубокой проверки пакетов (DPI), которые используются многими интернет-провайдерами для блокировки доступа к определённым сайтам.

Оно работает с Пассивным DPI, подключённым с помощью оптического сплиттера или зеркалирования порта, который не блокирует данные, а просто отвечает быстрее, чем запрашиваемый адрес назначения, а также с Активным DPI, подключённым последовательно.

Требуется **Windows 7, 8, 8.1, 10 или 11** с правами администратора.

# Быстрый старт

* **Для России**: Скачайте [последнюю версию со страницы релизов](https://github.com/ValdikSS/GoodbyeDPI/releases), распакуйте файл и запустите скрипт **1_russia_blacklist_dnsredir.cmd**.
* Для других стран: Скачайте [последнюю версию со страницы релизов](https://github.com/ValdikSS/GoodbyeDPI/releases), распакуйте файл и запустите скрипт **2_any_country_dnsredir.cmd**.

Эти скрипты запускают GoodbyeDPI в рекомендованном режиме с перенаправлением DNS-запросов на Yandex DNS через нестандартный порт (чтобы предотвратить подмену DNS).  
Если это работает — поздравляем! Вы можете использовать его как есть или настроить дальше.

# Как использовать

Скачайте [последнюю версию со страницы релизов](https://github.com/ValdikSS/GoodbyeDPI/releases) и запустите.

```
Usage: goodbyedpi.exe [OPTION...]
 -p          block passive DPI
 -q          block QUIC/HTTP3
 -r          replace Host with hoSt
 -s          remove space between host header and its value
 -m          mix Host header case (test.com -> tEsT.cOm)
 -f <value>  set HTTP fragmentation to value
 -k <value>  enable HTTP persistent (keep-alive) fragmentation and set it to value
 -n          do not wait for first segment ACK when -k is enabled
 -e <value>  set HTTPS fragmentation to value
 -a          additional space between Method and Request-URI (enables -s, may break sites)
 -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)
 --port        <value>    additional TCP port to perform fragmentation on (and HTTP tricks with -w)
 --ip-id       <value>    handle additional IP ID (decimal, drop redirects and TCP RSTs with this ID).
                          This option can be supplied multiple times.
 --dns-addr    <value>    redirect UDP DNS requests to the supplied IP address (experimental)
 --dns-port    <value>    redirect UDP DNS requests to the supplied port (53 by default)
 --dnsv6-addr  <value>    redirect UDPv6 DNS requests to the supplied IPv6 address (experimental)
 --dnsv6-port  <value>    redirect UDPv6 DNS requests to the supplied port (53 by default)
 --dns-verb               print verbose DNS redirection messages
 --blacklist   <txtfile>  perform circumvention tricks only to host names and subdomains from
                          supplied text file (HTTP Host/TLS SNI).
                          This option can be supplied multiple times.
 --allow-no-sni           perform circumvention if TLS SNI can't be detected with --blacklist enabled.
 --frag-by-sni            if SNI is detected in TLS packet, fragment the packet right before SNI value.
 --set-ttl     <value>    activate Fake Request Mode and send it with supplied TTL value.
                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).
 --auto-ttl    [a1-a2-m]  activate Fake Request Mode, automatically detect TTL and decrease
                          it based on a distance. If the distance is shorter than a2, TTL is decreased
                          by a2. If it's longer, (a1; a2) scale is used with the distance as a weight.
                          If the resulting TTL is more than m(ax), set it to m.
                          Default (if set): --auto-ttl 1-4-10. Also sets --min-ttl 3.
                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).
 --min-ttl     <value>    minimum TTL distance (128/64 - TTL) for which to send Fake Request
                          in --set-ttl and --auto-ttl modes.
 --wrong-chksum           activate Fake Request Mode and send it with incorrect TCP checksum.
                          May not work in a VM or with some routers, but is safer than set-ttl.
 --wrong-seq              activate Fake Request Mode and send it with TCP SEQ/ACK in the past.
 --native-frag            fragment (split) the packets by sending them in smaller packets, without
                          shrinking the Window Size. Works faster (does not slow down the connection)
                          and better.
 --reverse-frag           fragment (split) the packets just as --native-frag, but send them in the
                          reversed order. Works with the websites which could not handle segmented
                          HTTPS TLS ClientHello (because they receive the TCP flow "combined").
 --max-payload [value]    packets with TCP payload data more than [value] won't be processed.
                          Use this option to reduce CPU usage by skipping huge amount of data
                          (like file transfers) in already established sessions.
                          May skip some huge HTTP requests from being processed.
                          Default (if set): --max-payload 1200.


LEGACY modesets:
 -1          -p -r -s -f 2 -k 2 -n -e 2 (most compatible mode)
 -2          -p -r -s -f 2 -k 2 -n -e 40 (better speed for HTTPS yet still compatible)
 -3          -p -r -s -e 40 (better speed for HTTP and HTTPS)
 -4          -p -r -s (best speed)

Modern modesets (more stable, more compatible, faster):
 -5          -f 2 -e 2 --auto-ttl --reverse-frag --max-payload
 -6          -f 2 -e 2 --wrong-seq --reverse-frag --max-payload
 -7          -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload
 -8          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload
 -9          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (this is the default)

 Note: combination of --wrong-seq and --wrong-chksum generates two different fake packets.
```

Чтобы проверить, можно ли обойти DPI вашего интернет-провайдера, сначала убедитесь, что ваш провайдер не подделывает ответы DNS, включив опцию "Безопасные DNS (DNS через HTTPS)" в вашем браузере.

* **Chrome**: Настройки → [Конфиденциальность и безопасность](chrome://settings/privacy) → [Безопасность](chrome://settings/security) → Использовать безопасный DNS-сервер → Выбрать пункт NextDNS или другой
* **Firefox**: [Настройки](about:preferences) → [Приватность и Защита](about:preferences#privacy) → DNS через HTTPS → Выбрать пункт "Максимальную защиту"

Затем запустите исполняемый файл `goodbyedpi.exe` без каких-либо опций. Если это работает — поздравляю! Вы можете использовать его как есть или настроить дальше, например, используя опцию `--blacklist`, если список заблокированных сайтов известен и доступен для вашей страны.

Если ваш провайдер перехватывает DNS запросы, возможно, вам стоит использовать опцию `--dns-addr` для публичного DNS-резольвера на нестандартном порте (например, Яндекс DNS `77.88.8.8:1253`) или настроить DNS через HTTPS/TLS с помощью сторонних приложений.

Проверьте скрипты .cmd и измените их в соответствии с вашими предпочтениями и условиями сети.

# Как это работает

### Пассивный DPI

Большинство пассивных DPI отправляют HTTP 302 Redirect, если вы пытаетесь получить доступ к заблокированному сайту через HTTP, и TCP Reset в случае HTTPS быстрее, чем целевой веб-сайт. Пакеты, отправляемые DPI, обычно имеют поле IP Identification, равное `0x0000` или `0x0001`, как это видно у российских провайдеров. Эти пакеты, если они перенаправляют вас на другой сайт (страницу цензуры), блокируются GoodbyeDPI.

### Активный DPI

Активный DPI более сложно обмануть. В настоящее время программное обеспечение использует 7 методов для обхода активного DPI:

* Фрагментация на уровне TCP для первого пакета данных
* Фрагментация на уровне TCP для постоянных (keep-alive) HTTP-сессий
* Замена заголовка `Host` на `hoSt`
* Удаление пробела между именем заголовка и значением в заголовке `Host`
* Добавление дополнительного пробела между методом HTTP (GET, POST и т.д.) и URI
* Изменение регистра значения заголовка Host
* Отправка поддельных HTTP/HTTPS пакетов с низким значением Time-To-Live, некорректной контрольной суммой или неверными номерами последовательности/подтверждения TCP, чтобы обмануть DPI и предотвратить доставку их к назначению

Эти методы не должны ломать сайты, так как они полностью совместимы со стандартами TCP и HTTP, однако их достаточно, чтобы предотвратить классификацию данных DPI и обойти цензуру. Дополнительный пробел может сломать некоторые сайты, хотя это допустимо согласно спецификации HTTP/1.1 (см. 19.3 Tolerant Applications).

Программа загружает драйвер WinDivert, который использует Windows Filtering Platform для установки фильтров и перенаправления пакетов в пользовательское пространство. Она работает до тех пор, пока консольное окно остаётся открытым, и завершает работу при закрытии окна.

# Как собрать из исходников

Этот проект можно собрать с помощью **GNU Make** и [**mingw**](https://mingw-w64.org). Единственная зависимость — [WinDivert](https://github.com/basil00/Divert).

Для сборки x86 exe выполните:

`make CPREFIX=i686-w64-mingw32- WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/x86`

А для x86_64:

`make CPREFIX=x86_64-w64-mingw32- BIT64=1 WINDIVERTHEADERS=/path/to/windivert/include WINDIVERTLIBS=/path/to/windivert/amd64`

# Как установить в качестве Службы Windows

Ознакомьтесь с примерами в скриптах `service_install_russia_blacklist.cmd`, `service_install_russia_blacklist_dnsredir.cmd` и `service_remove.cmd`.

Измените их в соответствии с вашими потребностями.

# Известные проблемы

* Ужасно устаревшие установки Windows 7 не могут загрузить драйвер WinDivert из-за отсутствия поддержки цифровых подписей SHA256. Установите KB3033929 [x86](https://www.microsoft.com/en-us/download/details.aspx?id=46078)/[x64](https://www.microsoft.com/en-us/download/details.aspx?id=46148), или лучше, обновите всю систему с помощью Windows Update.
* ~~Некоторые SSL/TLS стеки не могут обрабатывать фрагментированные пакеты ClientHello, и HTTPS сайты не открываются. Ошибка: [#4](https://github.com/ValdikSS/GoodbyeDPI/issues/4), [#64](https://github.com/ValdikSS/GoodbyeDPI/issues/64).~~ Проблемы с фрагментацией исправлены в версии v0.1.7.
* ~~Антивирус ESET несовместим с драйвером WinDivert [#91](https://github.com/ValdikSS/GoodbyeDPI/issues/91). Это, вероятно, ошибка антивируса, а не WinDivert.~~

# Похожие проекты

- **[zapret](https://github.com/bol-van/zapret)** от @bol-van (для MacOS, Linux и Windows)
- **[Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)** от @SadeghHayeri (для MacOS, Linux и Windows)
- **[DPI Tunnel CLI](https://github.com/nomoresat/DPITunnel-cli)** от @zhenyolka (для Linux и маршрутизаторов)
- **[DPI Tunnel for Android](https://github.com/nomoresat/DPITunnel-android)** от @zhenyolka (для Android)
- **[PowerTunnel](https://github.com/krlvm/PowerTunnel)** от @krlvm (для Windows, MacOS и Linux)
- **[PowerTunnel for Android](https://github.com/krlvm/PowerTunnel-Android)** от @krlvm (для Android)
- **[SpoofDPI](https://github.com/xvzc/SpoofDPI)** от @xvzc (для macOS и Linux)
- **[GhosTCP](https://github.com/macronut/ghostcp)** от @macronut (для Windows)
- **[ByeDPI](https://github.com/hufrea/byedpi)** для Linux/Windows + **[ByeDPIAndroid](https://github.com/dovecoteescapee/ByeDPIAndroid/)** для Android (без root)

# Благодарности

Спасибо @basil00 за [WinDivert](https://github.com/basil00/Divert). Это основная часть этой программы.

Спасибо каждому участнику [BlockCheck](https://github.com/ValdikSS/blockcheck). Было бы невозможно понять поведение DPI без этой утилиты.
