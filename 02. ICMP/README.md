# Packet Capture

pcap 라이브러리를 활용해 Internet Control Message Protocol (ICMP) 패킷을 보내보자

## Compile and Run

```bash
make
sudo ./icmp <target ip>
```
or 
```bash
gcc main.c -o icmp -lpcap
sudo ./icmp <target ip>
```

## ICMP

| 1 Byte | 1 Byte | 2 Bytes | Other |
|:------:|:------:|:-------:|:-----:|
| Type   | Code   | ICMP Checksum | Data |

Type 0은 Echo Reply, 1은 Echo Request

더 자세한 것은 [이곳](http://ktword.co.kr/abbr_view.php?nav=0&m_temp1=5465&id=423) 참고

## 그 외

이번에는 인터페이스의 맥주소와 아이피 주소를 알아낼 필요가 있었다.

이를 위해 소켓을 열고 소켓에서 정보를 받아오는 방식을 활용했다.

하지만 이는 윈도우에서 사용할 수 없다.

윈도우에서 인터페이스의 맥주소와 아이피 주소를 알아내는 방법을 찾을 필요가 있다.