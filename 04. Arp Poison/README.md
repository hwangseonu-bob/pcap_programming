# ARP Poison

arp를 통해 네트워크 장치들은 어떤 장치가 어떤 ip를 가지고 있는지 알 수 있으며 
이를 통해 만들어진 arp table을 이용해 통신을 하게 된다.

하지만 arp에 거짓된 정보가 들어있다면 어떻게 될까?
arp table은 arp를 통해 갱신되기 때문에 거짓된 정보가 arp에 들어있다 하더라도 arp table은 갱신된다.
이러한 arp의 약점을 이용한 공격이 바로 arp spoofing이다.

이번에는 arp spoofing을 본격적으로 다루진 않고 arp 패킷에 거짓된 정보를 넣어 보내는 부분만 구현해보자.

[arp spoofing 을 구현한 레포](https://github.com/hwangseonu/arp_spoof)


## Compile and Run

```bash
make
sudo ./arp_poison <network interface> <victim address>
```
or 
```bash
gcc main.c -o arp_poison -lpcap
sudo ./arp_poison
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

### 방법

arp table을 오염시키는 방법은 간단하다.
arp header 에 sender ip 필드에 게이트웨이의 아이피를 넣고 sender mac에 자신의 컴퓨터의 맥주소를 적는다.
target mac과 target ip는 오염시킬 장비의 주소를 넣어 보내기만 하면
target에서는 받은 arp 패킷을 이용해 arp table을 업데이트 한다.


