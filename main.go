package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	oodle "market/oodle"
	parser "market/packet/market_search"

	pb "market/rpc"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	xor_key, _ = ioutil.ReadFile("assets/xor.bin")
	rpcClient  pb.MessageServiceClient
)

var devicecNameFlag = flag.String("device", "none", "device name")

func xorCipher(data []byte, seed int, xorKey []byte) {
	for i := 0; i < len(data); i++ {
		data[i] ^= xorKey[seed%len(xorKey)]
		seed++
	}
}

func selectInterface() string {
	interfaces, err := pcap.FindAllDevs()

	if err != nil {
		panic(err)
	}

	for i, iface := range interfaces {
		println(i, iface.Name)
	}

	var selected int

	println("Select interface: ")

	_, err = fmt.Scanf("%d", &selected)

	if err != nil {
		panic(err)
	}

	return interfaces[selected].Name
}

func sniffer(processPacket func([]byte)) {
	var interfaceName string

	if *devicecNameFlag == "none" {
		interfaceName = selectInterface()
	} else {
		interfaceName = *devicecNameFlag
	}

	println("Starting sniffer on interface: ", interfaceName)

	handle, err := pcap.OpenLive(interfaceName, 65536, false, 3)

	if err != nil {
		panic(err)
	}

	filter := "tcp src port 6040"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		if packet.ApplicationLayer() == nil {
			continue
		}

		processPacket(packet.ApplicationLayer().Payload())
	}

}

func processPacket(raw []byte) {

	AuctionSearchOpCode := 36394

	packet_size := binary.LittleEndian.Uint16(raw[0:2])
	op_code := binary.LittleEndian.Uint16(raw[2:4])

	if int(op_code) != AuctionSearchOpCode {
		return
	}

	xorCipher(raw[6:packet_size], int(op_code), xor_key)

	decompressed, err := oodle.Decompress(raw[6:packet_size])

	if err != nil {
		panic(err)
	}

	parser.ParseData(decompressed, rpcClient)

}

func getRpc() (pb.MessageServiceClient, *grpc.ClientConn) {
	conn, err := grpc.Dial("0.0.0.0:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		println("RPC Server offline, ignoring...")
		return nil, nil
	}

	println("RPC client connected")

	client := pb.NewMessageServiceClient(conn)

	// response, err := client.SayHello(context.Background(), &pb.HelloRequest{Name: "From Golang"})

	// if err != nil {
	// 	panic(err)
	// }
	// println(response.Message)

	return client, conn
}

func main() {

	flag.Parse()

	oodle.Init()

	var conn *grpc.ClientConn

	rpcClient, conn = getRpc()

	defer conn.Close()

	sniffer(processPacket)
}
