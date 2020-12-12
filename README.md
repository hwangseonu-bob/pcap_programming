# pcap programming

**pcap 라이브러리** 사용 관련하여 공부한 내용들을 정리한 레포지스토리 입니다.

**pcap 라이브러리**는 네트워크 패킷 캡처 라이브러리로 패킷을 캡처하고 다루기 위한 라이브러리 입니다.

네트워크 패킷 캡처 및 분석 기능을 구현할 때 pcap 라이브러리를 사용하면 편하다.
대표적인 패킷 캡처 도구인 `tcpdump`도 pcap 라이브러리로 구현되어 있다.

이 레포지스토리의 모든 소스코드는 **Ubuntu** 리눅스 환경에서 개발되었으며
윈도우 등의 다른 운영체제에서는 작동하지 않을 수 있다. 

## 설치

우분투 리눅스에서 pcap 라이브러리를 설치하기 위해서는 아래의 명령어를 사용하면 된다.

```bash
sudo apt install -y libpcap-dev
```

[tcpdump.org](tcpdump.org) 에서 직접 받아 컴파일하여 사용할 수도 있다.

## 주요 함수

```c
// 인터페이스의 네트워크 주소, 마스크 정보를 가져오는 함수
int pcap_lookupnet(char *device, bpf_u_int32 *netp, 
                   bpf_u_int32 *maskp, char *errbuf);
```

```c
// pcap 라이브러리에서 사용할 인터페이스의 이름을 가져오는 함수
char* pcap_lookupdev(char *errbuf);
```

```c
// 네트워크 인터페이스로 pcap 라이브러리를 사용하기 위한 함수
pcap_t* pcap_open_live(const char *device, int snaplen, 
                       int promisc, int to_ms, char *errbuf);
```

```c
// pcap 파일로 pcap 라이브러리를 사용하기 위한 함수
pcap_t* pcap_open_offline(const char *filename, char *errbuf);
```

```c
// 사용이 끝난 pcap 포인터를 정리하는 함수 (free)
void pcap_close(pcap_t *p);
```

```c
// pcap 라이브러리로 부터 다음 패킷 정보를 받는 함수
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
        const u_char **pkt_data);
```

## 컴파일

gcc를 이용하여 컴파일 할 때 pcap 라이브러리를 사용한다는 것을 명시하여야 한다.

pcap 라이브러리를 사용한다고 명시하지 않을 경우 컴파일 에러가 발생한다.

```bash
gcc <소스파일.c> -o <실행파일> -lpcap
```

이 레포지스토리는 **Makefile**를 사용하므로 **make**를 이용하여 컴파일 할 수 있다.

```bash
make
```

## 실행

pcap 라이브러리를 활용하여 개발된 프로그램은 동작할 때 root 권한이 필요하다.

```bash
sudo ./<실행파일>
```

## TODO

- [ ] 윈도우에서도 동작 할 수 있도록 wpcap 사용 방법 추가 
- [ ] Make 대신 CMake 사용
