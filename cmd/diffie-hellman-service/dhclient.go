package main

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"log"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var DefaultConfigFile = "/config/config-adapter.json"
var DefaultDhConfigFile = "/config/config-dh.json"
var configDataPtr *ClientConfig
var configDhDataPtr *DhConfig
var seqNo int32 = 0
var err error

var dhCli DhGrpcServiceClient

func initSignalHandle() {
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		// Run Cleanup
		fmt.Println("Receive: get exit signal, exit now.")
		os.Exit(1)
	}()
}

func test() error {
	p, _ := Prime(int(configDhDataPtr.DhParams.KeySize))
	g := big.NewInt(int64(configDhDataPtr.DhParams.G))

	alice := NewDh()
	alice.P = p
	alice.G = g

	bob := NewDh()
	bob.P = p
	bob.G = g

	fmt.Println("P:", p)
	fmt.Println("G:", g)

	start := time.Now()

	alice.PrivateKey, _ = Prime(int(configDhDataPtr.DhParams.KeySize))
	bob.PrivateKey, _ = Prime(int(configDhDataPtr.DhParams.KeySize))

	alice.AnswerKey = bob.Public()
	bob.AnswerKey = alice.Public()

	fmt.Println("alice PrivateKey:", alice.PrivateKey)
	fmt.Println("bob   PrivateKey:", bob.PrivateKey)

	fmt.Println("alice AnswerKey:", alice.AnswerKey)
	fmt.Println("bob   AnswerKey:", bob.AnswerKey)

	fmt.Println("alice computes:", alice.Computes())
	fmt.Println("bob   computes:", bob.Computes())

	fmt.Println("alice sha256:", alice.Sha256())
	fmt.Println("bob   sha256:", bob.Sha256())

	fmt.Printf("Duration t:%v\n\n", time.Since(start).Seconds())

	time.Sleep(1 * time.Second)

	return nil
}

func ping(client DhGrpcServiceClient, ping string) error {
	var in PingPongMessage

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in.Msg = ping
	answer, err := client.Ping(ctx, &in)
	if err != nil {
		log.Println("Ping ERROR:", err)
	} else {
		log.Println("Ping answer:", answer.Msg)
	}
	return err
}

func xchgMessage(client DhGrpcServiceClient, seqNo uint64, data string) error {
	var in EncMessage

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	in.Seqno = int64(seqNo)
	in.Data = data
	answer, err := client.XchgMessage(ctx, &in)
	if err != nil {
		log.Println("SendMessage ERROR:", err)
	} else {
		fmt.Println("SendMessage returned:", answer.RetCode)
	}

	return err
}

func cliXchgKey(client DhGrpcServiceClient, seqNo uint64, pubKey []byte) ([]byte, error) {
	var in PKeyMessage

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	in.Seqno = int64(seqNo)
	in.Pubkey = pubKey
	answer, err := client.CliXchgKey(ctx, &in)
	if err != nil {
		log.Println("CliXchgKey ERROR:", err)
		return nil, err
	}
	return answer.Pubkey, err
}

func calcPrivKey(client DhGrpcServiceClient, seqNo uint64) (sha string, err error) {
	alice := NewDh()
	alice.P = new(big.Int)
	alice.G = new(big.Int)
	alice.P.SetBytes([]byte(configDhDataPtr.DhParams.P))
	alice.G.SetUint64(uint64(configDhDataPtr.DhParams.G))

	alice.PrivateKey, _ = Prime(int(configDhDataPtr.DhParams.KeySize))

	bobPublic, err := cliXchgKey(client, seqNo, alice.Public().Bytes())

	alice.AnswerKey = new(big.Int)
	if err == nil {
		alice.AnswerKey.SetBytes(bobPublic)
	} else {
		alice.AnswerKey.SetUint64(0)
	}

	// fmt.Println("Public Key:", alice.Public())
	// fmt.Println("alice PrivateKey:", alice.PrivateKey)

	// fmt.Println("alice AnswerKey:", alice.AnswerKey)
	sha = alice.Sha256()

	// fmt.Println("alice computes:", alice.Computes())

	// fmt.Println("alice sha256:", sha)

	return sha, nil
}

func main() {

	initSignalHandle()
	fmt.Println("Diffie-Hellman gRPC client application")

	// Initialize configuration
	for {
		configDataPtr = initConfig(DefaultConfigFile)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}

	var conn *grpc.ClientConn
	var err error

	for {
		var opts []grpc.DialOption

		// Initialize configuration
		configDataPtr = initConfig(DefaultConfigFile)

		if configDataPtr.GrpcServerConfig.TlsEnable {
			creds, err := credentials.NewClientTLSFromFile(configDataPtr.GrpcServerConfig.CertFile, "csp.ge.com")
			if err != nil {
				log.Fatalf("Failed to create TLS credentials %v", err)
			}
			opts = append(opts, grpc.WithTransportCredentials(creds))
		} else {
			opts = append(opts, grpc.WithInsecure())
		}

		srv := fmt.Sprintf("%s:%d", configDataPtr.GrpcServerConfig.Url, configDataPtr.GrpcServerConfig.Port)
		conn, err = grpc.Dial(srv, opts...)
		if err != nil {
			log.Fatalf("fail to dial: %v", err)
		}

		dhCli = NewDhGrpcServiceClient(conn)

		// Check the server connection
		err = ping(dhCli, "PING")
		if err != nil {
			time.Sleep(3 * time.Second)
		} else {
			break

		}
	}

	// Initialize diffie-hellman interface
	for {
		configDhDataPtr = initDhConfig(DefaultDhConfigFile)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println("Diffie-Hellman gRPC client application initialization - DONE")
	var seqNo uint64 = 1
	for {
		start := time.Now()

		sha, _ := calcPrivKey(dhCli, seqNo)

		data := encrypt("The quick brown fox jumps over the lazy dog", sha)
		fmt.Printf("%d.Encripted data = %s\n", seqNo, data)

		xchgMessage(dhCli, seqNo, data)
		fmt.Printf("%d.Msg xchg duration t:%f\n\n", seqNo, time.Since(start).Seconds())
		seqNo++

		time.Sleep(1 * time.Second)
	}
}
