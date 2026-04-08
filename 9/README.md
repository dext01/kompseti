**Сначала я создал Docker-сеть типа bridge с поддержкой Dual Stack (одновременная работа IPv4 и IPv6).**
```
docker network create \
  --driver bridge \
  --ipv6 \
  --subnet=fd00:dead:beef:c0::/64 \
  --gateway=fd00:dead:beef:c0::1 \
  ipv6-lab
```

**Я запустил два контейнера на базе образа Alpine.**
```
# Запуск сервера
docker run -dit --name server --net ipv6-lab --ip6 fd00:dead:beef:c0::2 alpine sleep infinity

# Запуск клиента
docker run -dit --name client --net ipv6-lab --ip6 fd00:dead:beef:c0::3 alpine sleep infinity
```

**Установил iputils и tcpdump для анализа сети внутри контейнера.**
```
docker exec server apk add --no-cache iputils tcpdump
docker exec client apk add --no-cache iputils tcpdump
```

**Запуск прослушивания на сервере и пинг с клиента, в терминале сервера:**
```
docker exec server tcpdump -i eth0 -nn -c 3 ip6
```
**Вывод:**
```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
11:54:31.011525 IP6 fd00:dead:beef:c0::3 > fd00:dead:beef:c0::2: ICMP6, echo request, id 7, seq 1, length 64
3 packets captured
4 packets received by filter
0 packets dropped by kernel
11:54:31.011545 IP6 fd00:dead:beef:c0::2 > fd00:dead:beef:c0::3: ICMP6, echo reply, id 7, seq 1, length 64
11:54:32.050791 IP6 fd00:dead:beef:c0::3 > fd00:dead:beef:c0::2: ICMP6, echo request, id 7, seq 2, length 64
```
**Запуск прослушивания на сервере и пинг с клиента, в терминале клиента:**
```
docker exec client ping6 -c 4 fd00:dead:beef:c0::2
```
**Вывод:**
```
PING fd00:dead:beef:c0::2 (fd00:dead:beef:c0::2) 56 data bytes
64 bytes from fd00:dead:beef:c0::2: icmp_seq=1 ttl=64 time=0.108 ms
64 bytes from fd00:dead:beef:c0::2: icmp_seq=2 ttl=64 time=0.089 ms

--- fd00:dead:beef:c0::2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1039ms
rtt min/avg/max/mdev = 0.089/0.098/0.108/0.009 ms
```

***Результат: В логах зафиксирован протокол ICMP6. Пакеты используют 128-битные шестнадцатеричные адреса.***

**Для сравнения был выполнен аналогичный тест через стандартный протокол IPv4:**

```
docker exec server tcpdump -i eth0 -nn -c 3 ip
```
**вывод:**
```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
11:54:47.773998 IP 172.20.0.3 > 172.20.0.2: ICMP echo request, id 8, seq 1, length 64
3 packets captured
4 packets received by filter
0 packets dropped by kernel
11:54:47.774022 IP 172.20.0.2 > 172.20.0.3: ICMP echo reply, id 8, seq 1, length 64
11:54:48.818882 IP 172.20.0.3 > 172.20.0.2: ICMP echo request, id 8, seq 2, length 64
```

**в терминале клиента:**
```
docker exec client ping -c 2 172.20.0.2
```
**вывод:**
```
PING 172.20.0.2 (172.20.0.2) 56(84) bytes of data.
64 bytes from 172.20.0.2: icmp_seq=1 ttl=64 time=0.067 ms
64 bytes from 172.20.0.2: icmp_seq=2 ttl=64 time=0.075 ms

--- 172.20.0.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1045ms
rtt min/avg/max/mdev = 0.067/0.071/0.075/0.004 ms
```

**Вывод по заданию:**
```
Формат адресов: IPv6 использует более длинную и сложную запись.
Протоколы: Пинг в IPv6 работает через специализированный стек ICMPv6.
Tcpdump: Четко разделяет трафик по меткам IP (v4) и IP6 (v6).
```
