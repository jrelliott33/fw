# Fw.py

Fw.py simplifies setting of iptables firewall rules

### Prerequisites

Python3

### Usage

```
usage: fw.py [-h] [-A ADD [ADD ...]] [-B BLOCK [BLOCK ...]]
             [-D DELETE [DELETE ...]] [-F] [-P] [-R] [-T] [-X]

optional arguments:
  -h, --help            show this help message and exit
  -A ADD [ADD ...], --add ADD [ADD ...]
                        Allow IP IP:PORT :PORT through firewall,
  -B BLOCK [BLOCK ...], --block BLOCK [BLOCK ...]
  -D DELETE [DELETE ...], --delete DELETE [DELETE ...]
  -F, --flush           Flush and Accept All
  -P, --print           Print Firewall Rules
  -R, --reset           reset default rules
  -T, --starttor        Start Kalitorify
  -X, --stoptor         Stop Kalitorify```

```

