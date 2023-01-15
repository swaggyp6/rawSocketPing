package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

type Echo struct {
	Type     byte
	Code     byte
	Checksum int
	Id       int
	Seq      int
	data     []byte
}

func (e *Echo) mashall() []byte {
	buf := make([]byte, 8, 20)
	buf[0] = e.Type
	buf[1] = e.Code
	buf = append(buf, e.data...)
	return buf
}

func CheckSum(data []byte) (rt uint16) {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index]) << 8
	}
	rt = uint16(sum) + uint16(sum>>16)

	return ^rt
}

// 1、 先将需要计算checksum数据中的checksum设为0；
// 2、 计算checksum的数据按2byte划分开来，每2byte组成一个16bit的值，如果最后有单个byte的数据，补一个byte的0组成2byte；
// 3、 将所有的16bit值累加到一个32bit的值中；
// 4、 将32bit值的高16bit与低16bit相加到一个新的32bit值中，若新的32bit值大于0Xffff，再将新值的高16bit与低16bit相加；
// 5、 将上一步计算所得的16bit值按位取反，即得到checksum值，存入数据的checksum字段即可
func myCsm(msg []byte) uint16 {
	var res uint32
	if len(msg)%2 == 1 {
		msg = append(msg, 0)
	}
	for i := 0; i < len(msg)-1; i = i + 2 {
		var mid uint16 = (uint16(msg[i])<<8 + uint16(msg[i+1]))
		res += uint32(mid)
	}
	res = uint32(uint16(res>>16&0xff) + uint16(res))
	if res > 0xffff {
		res = uint32(uint16(res>>16&0xff) + uint16(res))
	}
	return ^uint16(res)
}

type IpveHead struct {
	Version                byte
	headerLen              byte
	TypeOfService          byte
	TotalLength            uint16
	Identification         uint16
	FlagsAndFragmentOffset uint16
	TimeToLive             byte
	Protocol               byte
	HeaderChecksum         uint16
	SrcAddr                uint32
	DstAddr                uint32
}

func IPToUInt32(ipnr net.IP) uint32 {
	bits := strings.Split(ipnr.String(), ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}
func (ih *IpveHead) MashallIp(msg []byte) []byte {
	dataGram := make([]byte, 20, 30)
	dataGram[0] |= ih.Version << 4 & 0xff
	dataGram[0] |= ih.headerLen
	dataGram[8] = ih.TimeToLive
	dataGram[9] = ih.Protocol
	dataGram[12] = byte(ih.SrcAddr >> 24)
	dataGram[13] = byte(ih.SrcAddr >> 16)
	dataGram[14] = byte(ih.SrcAddr >> 8)
	dataGram[15] = byte(ih.SrcAddr)
	dataGram[16] = byte(ih.DstAddr >> 24)
	dataGram[17] = byte(ih.DstAddr >> 16)
	dataGram[18] = byte(ih.DstAddr >> 8)
	dataGram[19] = byte(ih.DstAddr)
	dataGram[2] = byte((len(dataGram) + len(msg)) >> 8)
	dataGram[3] = byte(len(dataGram) + len(msg))
	csm := CheckSum(dataGram)
	dataGram[10] = byte(csm >> 8)
	dataGram[11] = byte(csm)
	dataGram = append(dataGram, msg...)
	return dataGram
}
func main() {
	echo := &Echo{Type: 8, Code: 0, data: []byte("hello rust")}
	msg := echo.mashall()
	csm := myCsm(msg)
	msg[2] = byte((csm >> 8) & 0xff)
	msg[3] = byte(csm)
	fmt.Println(msg)
	ip4 := &IpveHead{
		Version:       4,
		headerLen:     5,
		TypeOfService: 0,
		TimeToLive:    55,
		Protocol:      1,
		SrcAddr:       IPToUInt32(net.ParseIP("127.0.0.8")),
		DstAddr:       IPToUInt32(net.ParseIP("127.0.0.4")),
	}
	mmmsg := ip4.MashallIp(msg)
	fmt.Println(mmmsg)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 4)
	if err != nil {
		return
	}
	inet4 := syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 7}}
	err = syscall.Sendto(fd, mmmsg, 0, &inet4)
	if err != nil {
		return
	}
}
