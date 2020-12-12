# Packet Capture

pcap 라이브러리를 활용해 Address Resolution Protocol (ARP) 패킷을 받아 정보를 출력해보자

## Compile and Run

```bash
make
sudo ./arp_capture
```
or 
```bash
gcc main.c -o arp_capture -lpcap
sudo ./arp_capture
```

## Arp

| 필드 | 크기 | 비고 |
|:---:|:---:|:---:|
| Hardware Type | 16bit | 이더넷은 1 |
| Protocol Type | 16bit | IP는 0x0800 |
| Hardware Length | 8bit | mac주소의 길이는 6byte |
| Protocol Length | 8bit | Ip주소의 길이는 4byte |
| Opcode | 16bit | 아래의 설명 참고 |
| Sender Mac | 48bit | 보내는 장치의 Mac주소 |
| Sender IP | 32bit | 보내는 장치의 IP주소 |
| Target Mac | 48bit | 받는 장치의 Mac주소(요청때는 0으로 비워둔다) |
| Target IP | 32bit | 받는 장치의 IP주소 |

### OPCODE

- 0x0001 (arp request) : 맥주소를 알려줄 것을 요청한다. Who has (IP)?
- 0x0002 (arp reply) : 맥주소를 패킷에 담아 보낸다. (IP) is at (MAC).
- 0x0003 (rarp request) : 아이피를 알려줄 것을 요청한다. Who has (MAC)?
- 0x0004 (rarp reply) : 아이피를 패킷에 담아 보낸다. (MAC) is at (IP)

### 한가지 의문

Ethernet header에도 source와 destination이 있는데 굳이 arp에도 sender mac과 target mac이 있어야할까?

#### 이에 대한 답 

Ethernet header에 있는 mac address는 통신을 위한 정보이지 arp table을 갱신하기 위한 정보가 아니다.

즉, ARP 테이블을 갱신 할 때는 ARP 헤더에 있는 정보만으로 갱신하게 된다.
소포를 예로 들면 Ethernet 헤더는 보내는 사람과 받는 사람이 적힌 종이이고 ARP 테이블을 갱신할때는 소포 안의 내용만 본다는 것.

## BPF

Berkeley Packet Filter 의 약자로 리눅스에서 지원하는 패킷을 필터링 하기 위해 사용되는 필터이다.

BPF에 대한 것은 내용이 너무 방대하기 때문에 추후에 따로 다루도록 함.

이번 프로젝트에는 `arp` 필터를 활용해 arp 패킷만 받도록 했음.




