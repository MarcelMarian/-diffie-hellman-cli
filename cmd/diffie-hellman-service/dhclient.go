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

// const KEY_SIZE = 512
// const P = "61271898154419322402913024440198123382732149960235057225471551559239770736436621747379793612734389078706272816399549319441301204844108985665478747484068105492425710020816744984827139634377543254232771701666641573615214190348551853310282985759862672269412349682391914493241981043233177573321010505440643093947263406385397608140232899472170776780135562173526944799247913033079971501369669327224164080476260790806304425757096764862596989528589162680331979843703607953840323045069341362184099475644229674957294550371"
const KEY_SIZE = 256
const P = "3238753880965754610707105568739490849904386530527757910159357650928335564145344807150033057961040728754572345258544588226658050311871620937068496966107379908371318841510184359376017486618971516252558874080687260635543277811155538694637753722244763834358971"
const G = 7

var DefaultConfigFile = "/config/config-adapter.json"
var configDataPtr *ClientConfig
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
	p, _ := Prime(KEY_SIZE)
	g := big.NewInt(5)

	alice := NewDh()
	alice.P = p
	alice.G = g

	bob := NewDh()
	bob.P = p
	bob.G = g

	fmt.Println("P:", p)
	fmt.Println("G:", g)

	start := time.Now()

	alice.PrivateKey, _ = Prime(KEY_SIZE)
	bob.PrivateKey, _ = Prime(KEY_SIZE)

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
	alice.P.SetBytes([]byte(P))
	alice.G.SetUint64(G)

	alice.PrivateKey, _ = Prime(KEY_SIZE)

	bobPublic, err := cliXchgKey(client, seqNo, alice.Public().Bytes())

	alice.AnswerKey = new(big.Int)
	if err == nil {
		alice.AnswerKey.SetBytes(bobPublic)
	} else {
		alice.AnswerKey.SetUint64(0)
	}

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
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	// Initialize gRPC interface
	fmt.Println("Diffie-Hellman gRPC client application initialization - DONE")

	var seqNo uint64 = 1
	for {
		start := time.Now()

		sha, _ := calcPrivKey(dhCli, seqNo)
		fmt.Printf("%d.Key xchg duration t:%v\n\n", seqNo, time.Since(start).Seconds())

		data := encrypt("The quick brown fox jumps over the lazy dog", sha)
		fmt.Printf("%d.Encripted data = %s\n", seqNo, data)

		xchgMessage(dhCli, seqNo, data)
		fmt.Printf("%d.Msg xchg duration t:%f\n\n", seqNo, time.Since(start).Seconds())
		seqNo++

		time.Sleep(1 * time.Second)
	}
}
