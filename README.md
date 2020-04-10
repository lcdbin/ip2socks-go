# ip2socks-go
 ip2socks go version

inspired by 
https://github.com/zfl9/ipt2socks


Test on archlinux and asus ac86u merlin ... 

```shell
$ ipt2socks-go --help  // no help option and use long style please ... ~~~~
usage: ipt2socks <options...>. the existing options are as follows:
 -s, --server-addr <addr>           socks5 server ip address, <required>
 -p, --server-port <port>           socks5 server port number, <required>
 -a, --auth-username <user>         username for socks5 authentication
 -k, --auth-password <passwd>       password for socks5 authentication
 -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1
 -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1
 -l, --listen-port <port>           listen port number, default: 60080
 -j, --thread-nums <num>            number of worker threads, default: 1
 -n, --nofile-limit <num>           set nofile limit, maybe need root priv
 -o, --udp-timeout <sec>            udp socket idle timeout, default: 300
 -c, --cache-size <size>            max size of udp lrucache, default: 256
 -f, --buffer-size <size>           buffer size of tcp socket, default: 8192
 -u, --run-user <user>              run the ipt2socks with the specified user
 -G, --graceful                     gracefully close the tcp connection pair
 -R, --redirect                     use redirect instead of tproxy (for tcp)
 -T, --tcp-only                     listen tcp only, aka: disable udp proxy
 -U, --udp-only                     listen udp only, aka: disable tcp proxy
 -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy
 -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy
 -v, --verbose                      print verbose log, default: <disabled>
 -V, --version                      print ipt2socks version number and exit
 -h, --help                         print ipt2socks help information and exit
```
