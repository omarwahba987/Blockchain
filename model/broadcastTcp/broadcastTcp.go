package broadcastTcp

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	"../cryptogrpghy"
	"../globalPkg"
	"../validator"
	"github.com/mitchellh/mapstructure"
)

var TempData []TCPData

//TCPData struct contain data about object,package name ,method
type TCPData struct {
	Obj         []byte
	ValidatorIP string
	Method      string
	PackageName string // CurrentTime        []string
	Signature   string
}
type NetStruct struct {
	Encryptedkey  string
	Encrypteddata string
}

type TxBroadcastResponse struct {
	TxID  string
	Valid bool
}
type FileBroadcastResponse struct {
	ChunkData []byte
	Valid     bool
}

const BUFFERSIZE = 1024

//TempNotRecieving IS store tcpdata an ip
// type TempNotRecieving struct {
// 	TCPData
// 	ValidatorSoketIP string
// }

// var temp []TempNotRecieving

//BoardcastingTCP Object
func BoardcastingTCP(obj interface{}, Method, PackageName string) (TxBroadcastResponse, FileBroadcastResponse) {
	var res TxBroadcastResponse

	var resFile FileBroadcastResponse
	for _, validatorObj := range validator.ValidatorsLstObj {
		if !validatorObj.ValidatorRemove {
			if validatorObj.ValidatorIP == validator.CurrentValidator.ValidatorIP {
				if PackageName == "transaction" && Method == "addTransaction" {
					_, res, _ = SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validator.CurrentValidator.ValidatorSoketIP)
					fmt.Println("\n @#########@ validatorIP", validatorObj.ValidatorIP, " and the res", res)
				} else if PackageName == "file" && Method == "getchunkdata" {
					fmt.Println("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
					_, _, resFile = SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
					fmt.Println("\n @#########@ validatorIP", validatorObj.ValidatorIP, " and the res", resFile)
				} else if PackageName == "file" && Method == "addchunk" {
					_, _, resFile = SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
				} else {
					SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validator.CurrentValidator.ValidatorSoketIP)
				}
			} else {
				if PackageName == "transaction" && Method == "addTransaction" {
					_, res, _ = SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
					fmt.Println("\n @#########@ validatorIP", validatorObj.ValidatorIP, " and the res", res)
				} else if PackageName == "file" && Method == "getchunkdata" {
					fmt.Println("::::::::::::::::::::::::::::::::::::::::::::::")
					_, _, resFile = SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
					fmt.Println("\n @#########@ validatorIP", validatorObj.ValidatorIP, " and the res", resFile)
				} else if PackageName == "file" && Method == "addchunk" {
					_, _, resFile = SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
				} else {
					SendObject(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
				}
			}
		}
	}
	return res, resFile
}

//SendObject to spacific miner
func SendObject(obj interface{}, Validatorpublickey, Method, PackageName, ValidatorSoketIP string) (TCPData, TxBroadcastResponse, FileBroadcastResponse) {

	var responseObj TxBroadcastResponse
	var responsechunkObj FileBroadcastResponse
	jsonObj, _ := json.Marshal(obj)
	// fmt.Println("\n **************** validator.CurrentValidator.ValidatorPrivateKey", validator.CurrentValidator.ValidatorPrivateKey)
	signature := cryptogrpghy.SignPKCS1v15(string(jsonObj), *cryptogrpghy.ParsePEMtoRSAprivateKey(validator.CurrentValidator.ValidatorPrivateKey))

	objTCP := TCPData{jsonObj, validator.CurrentValidator.ValidatorIP, Method, PackageName, signature}

	// conn, err := net.Dial("tcp", ValidatorSoketIP)
	// if err != nil {
	// 	fmt.Println("error at at net.dial")
	// 	fmt.Println(err)
	// 	return objTCP, responseObj, responsechunkObj
	// }
	// defer conn.Close()
	netObj := NetStruct{}

	/*---------------------------*/
	hashedkey := cryptogrpghy.CreateSHA1(Validatorpublickey)
	// netObj.Encryptedkey = cryptogrpghy.RSAENC(Validatorpublickey, []byte(hashedkey))
	netObj.Encryptedkey, _ = cryptogrpghy.PublicEncrypt(Validatorpublickey, hashedkey)
	byteData, _ := json.Marshal(objTCP)
	strofdata := string(byteData)
	netObj.Encrypteddata = cryptogrpghy.KeyEncrypt(hashedkey, strofdata)

	//conn, err := net.Dial("tcp", ValidatorSoketIP)
	// if err != nil {
	// 	fmt.Println("error at at net.dial")
	// 	fmt.Println(err)
	// 	return objTCP, responseObj, responsechunkObj
	// } else {

	byteData, _ = json.Marshal(netObj)
	strerr, returnByte := globalPkg.SendBroadCast(byteData, ValidatorSoketIP+"/a021d8007a2c590bc64ff2338d34c4e2", "POST")
	// hashpk := globalPkg.GetHash([]byte(Validatorpublickey))
	// tim := strconv.Itoa(int(time.Now().Unix()))
	// // newFile, err := os.Create("_" + fileName)
	// // path := "files"
	// // if _, err := os.Stat(path); os.IsNotExist(err) {
	// // 	os.Mkdir(path, 0777)
	// // }
	// str := "ino" + tim + "_" + hashpk[0:16] + "_" + PackageName + ".txt"
	// ioutil.WriteFile(str, byteData, 0644)

	// // file, err1 := os.Open(path + "/" + str)
	// file, err1 := os.Open(str)
	// defer file.Close()
	// if err1 != nil {
	// 	fmt.Println("error2", err)
	// 	return objTCP, responseObj, responsechunkObj
	// }
	// fileInfo, err := file.Stat()
	// if err != nil {
	// 	fmt.Println(err)
	// 	return objTCP, responseObj, responsechunkObj
	// }

	// fileSize := FillString(strconv.FormatInt(fileInfo.Size(), 10), 10)
	// conn.Write([]byte(fileSize))
	// fileName := FillString(fileInfo.Name(), 128)
	// conn.Write([]byte(fileName))
	// // fmt.Println("Start sending file!", fileName, " ", fileSize)
	// sendBuffer := make([]byte, BUFFERSIZE)
	// for {
	// 	_, err = file.Read(sendBuffer)
	// 	if err == io.EOF {
	// 		break
	// 	}
	// 	conn.Write(sendBuffer)
	// }
	// fmt.Println("File has been sent, closing connection!")
	// _, err := conn.Write(byteData)
	// fmt.Println("ChunkData .. ", len(byteData))
	//n, _ := fmt.Fprintf(conn, string(byteData))
	//var sizewrite int
	// if len(string(byteData))%256 == 0 {
	// 	fmt.Fprintf(conn, string(byteData)+" ")
	// 	sizewrite = len(string(byteData)) + 1
	// } else {
	// 	fmt.Fprintf(conn, string(byteData))
	// 	sizewrite = len(string(byteData))
	// }

	// conn.Write([]byte(FillString(strconv.Itoa(len(byteData)), 64)))
	// sendBuffer := make([]byte, BUFFERSIZE)
	// for index := 0; index <= len(byteData); index = index + BUFFERSIZE {
	// 	if index+BUFFERSIZE >= len(byteData) {
	// 		sendBuffer = byteData[index:len(byteData)]
	// 	} else {
	// 		sendBuffer = byteData[index : index+BUFFERSIZE]
	// 	}
	// 	conn.Write(sendBuffer)
	// }
	// //fmt.Println("file uploaded")
	// //fmt.Println("KOK +++++++", n)
	// if err != nil {
	// 	fmt.Println("broadcastTcp Write data error:", err)
	// }
	// time.Sleep(time .Second * 10)

	if objTCP.PackageName == "transaction" && Method == "addTransaction" {
		// responseObj = ReadTxResponseData(conn, str)
		if strerr != "" {
			responseObj.Valid = true
			// responseObj.TxID =
		} else {
			json.Unmarshal(returnByte, &responseObj)
		}
	}

	if objTCP.PackageName == "file" && Method == "getchunkdata" {
		if strerr != "" {
			responsechunkObj.Valid = false
			// responseObj.TxID =
		} else {
			json.Unmarshal(returnByte, &responsechunkObj)
		}
		// ChunkData []byte
		// Valid
		// responsechunkObj = ReadChunkResponse(conn, str)
	}

	if objTCP.PackageName == "file" && Method == "addchunk" {
		if strerr != "" {
			responsechunkObj.Valid = false
			// responseObj.TxID =
		} else {
			json.Unmarshal(returnByte, &responsechunkObj)
		}
		// ChunkData []byte
		// Valid
		// responsechunkObj = ReadChunkResponse(conn, str)
	}
	// file.Close()
	// var errx = os.Remove(str)
	// if errx != nil {
	// 	fmt.Println(errx)
	// }

	// }
	// fmt.Println("\n responseObj := ReadTxResponseData(conn)", responseObj)
	return objTCP, responseObj, responsechunkObj
}

func ReadTxResponseData(conn net.Conn, fileName string) TxBroadcastResponse {
	var txResponse TxBroadcastResponse

	// buffer := make([]byte, 1024)
	// // n, _, err1 := conn.ReadFromUDP(buffer)
	// n, err1 := conn.Read(buffer)
	// fmt.Println("UDP Server read bytes count: ", n)

	// ObjectBuferSize := make([]byte, 64)
	// conn.Read(ObjectBuferSize)
	// ObjectSize, _ := strconv.Atoi(strings.Trim(string(ObjectBuferSize), ":"))
	// fmt.Println(ObjectSize)
	// buf := []byte{}
	// tempbuf := make([]byte, BUFFERSIZE)

	// for index := 0; index <= ObjectSize; index = index + BUFFERSIZE {

	// 	n, err := conn.Read(tempbuf)
	// 	if err != nil {
	// 		if err != io.EOF {
	// 			fmt.Println("read error:", err)
	// 		}
	// 		break
	// 	}
	// 	//fmt.Println("got", n, "bytes.")

	// 	buf = append(buf, tempbuf[:n]...)

	// }
	// defer conn.Close()
	bufferFileSize := make([]byte, 10)

	conn.Read(bufferFileSize)
	fileSize, _ := strconv.ParseInt(strings.Trim(string(bufferFileSize), ":"), 10, 64)
	newFile, errf := os.Open(fileName)
	if errf != nil {
		fmt.Println(errf)
	}
	defer newFile.Close()
	var receivedBytes int64

	for {
		if (fileSize - receivedBytes) < BUFFERSIZE {
			io.CopyN(newFile, conn, (fileSize - receivedBytes))
			conn.Read(make([]byte, (receivedBytes+BUFFERSIZE)-fileSize))
			break
		}
		io.CopyN(newFile, conn, BUFFERSIZE)
		receivedBytes += BUFFERSIZE
	}
	// fmt.Println("Received file completely!", fileName, "", fileSize)
	// fn := "_" + fileName
	// file2, _ := os.Open(path + "/" + fn)
	file2, _ := os.Open("_" + fileName)
	fileBytes, _ := ioutil.ReadAll(file2)
	defer file2.Close()
	err2 := json.Unmarshal(fileBytes, &txResponse)
	fmt.Println("\n json.Unmarshal(buffer[:n], &txResponse) error: ", err2)
	var txResponse2 TxBroadcastResponse
	mapstructure.Decode(txResponse, &txResponse2) //smart life hack
	fmt.Println("the Response from broadcast handle:", txResponse2)

	// if err1 != nil {
	// 	fmt.Println("broadcastTcp read data error1:", err1)
	// }
	return txResponse2
}

// ReadChunkResponse read chunk response
func ReadChunkResponse(conn net.Conn, fileName string) FileBroadcastResponse {
	var chnkResponse FileBroadcastResponse

	//buffer := make([]byte, 1024)
	//var buffer bytes.Buffer
	//	n, _, err1 := conn.ReadFromUDP(buffer)
	//	fmt.Println("Start reading ...")
	//	n, err1 := conn.Read(buffer)
	//n, err1 := io.Copy(&buffer, conn)
	//	fmt.Println("UDP Server read bytes count: ", n)

	//	err2 := json.Unmarshal(buffer[:n], &chnkResponse)
	//err2 := json.Unmarshal(buffer.Bytes(), &chnkResponse)
	//	fmt.Println("\n json.Unmarshal(buffer[:n], &txResponse) error: ", err2)

	//	fmt.Println("the Response from broadcast handle:", chnkResponse)
	// var buf []byte
	// tmp := make([]byte, 256) // using small tmo buffer for demonstrating
	// for {
	// 	fmt.Println("88888start8888888888")
	// 	n, err := conn.Read(tmp)
	// 	fmt.Println("+++66666666666+++++++++++", n)
	// 	if err != nil {
	// 		if err != io.EOF {
	// 			fmt.Println("read error:", err)
	// 		}
	// 		break
	// 	}
	// 	//fmt.Println("got", n, "bytes.")
	// 	buf = append(buf, tmp[:n]...)
	// }
	// fmt.Println("END FORLOOP.............................")
	// fmt.Println("total size:", len(buf))
	// b := []byte(buf)
	// // if err1 != nil {
	// // 	fmt.Println("broadcastTcp read data error1:", err1)
	// // }
	// json.Unmarshal(b, &chnkResponse)
	bufferFileSize := make([]byte, 10)

	conn.Read(bufferFileSize)
	fileSize, _ := strconv.ParseInt(strings.Trim(string(bufferFileSize), ":"), 10, 64)
	newFile, errf := os.Open(fileName)
	if errf != nil {
		fmt.Println(errf)
	}
	defer newFile.Close()
	var receivedBytes int64

	for {
		if (fileSize - receivedBytes) < BUFFERSIZE {
			io.CopyN(newFile, conn, (fileSize - receivedBytes))
			conn.Read(make([]byte, (receivedBytes+BUFFERSIZE)-fileSize))
			break
		}
		io.CopyN(newFile, conn, BUFFERSIZE)
		receivedBytes += BUFFERSIZE
	}
	// fmt.Println("Received file completely!", fileName, "", fileSize)
	// fn := "_" + fileName
	// file2, _ := os.Open(path + "/" + fn)
	file2, _ := os.Open("_" + fileName)
	fileBytes, _ := ioutil.ReadAll(file2)
	defer file2.Close()

	err2 := json.Unmarshal(fileBytes, &chnkResponse)
	fmt.Println("\n json.Unmarshal(buffer[:n], &txResponse) error: ", err2)

	var chnkRspns2 FileBroadcastResponse
	// fmt.Println("SSSS ", string(chnkRspns2.ChunkData))
	mapstructure.Decode(chnkResponse, &chnkRspns2) //smart life hack
	return chnkRspns2
}

func SendTokenImg(obj string, Validatorpublickey, Method, PackageName, ValidatorSoketIP string) TCPData {
	jsonObj, _ := json.Marshal(obj)
	// signature := cryptogrpghy.SignPKCS1v15(string(jsonObj), *cryptogrpghy.ParsePEMtoRSAprivateKey(validator.CurrentValidator.ValidatorPrivateKey))

	objTCP := TCPData{jsonObj, validator.CurrentValidator.ValidatorIP, Method, PackageName, ""}
	// RemoteAddr, err := net.ResolveUDPAddr("udp", ValidatorSoketIP)
	// conn, err := net.DialUDP("udp", nil, RemoteAddr)
	// conn, err := net.Dial("tcp", ValidatorSoketIP)
	// if err != nil {
	// 	fmt.Println("error at at net.dial")
	// 	fmt.Println(err)
	// }
	// defer conn.Close()
	netObj := NetStruct{}

	// hashedkey := cryptogrpghy.CreateSHA1(Validatorpublickey)
	netObj.Encryptedkey = "key"
	byteDat, _ := json.Marshal(objTCP)
	strofdata := string(byteDat)
	netObj.Encrypteddata = strofdata //cryptogrpghy.KeyEncrypt(hashedkey, strofdata)

	// conn, err := net.Dial("tcp", ValidatorSoketIP)
	// if err != nil {
	// 	fmt.Println("error at at net.dial")
	// 	fmt.Println(err)

	// } else {
	byteData, _ := json.Marshal(netObj)
	globalPkg.SendBroadCast(byteData, ValidatorSoketIP+"/a021d8007a2c590bc64ff2338d34c4e2", "POST")
	// hashpk := globalPkg.GetHash([]byte(Validatorpublickey))
	// tim := strconv.Itoa(int(time.Now().Unix()))
	// // newFile, err := os.Create("_" + fileName)
	// // path := "files"
	// // if _, err := os.Stat(path); os.IsNotExist(err) {
	// // 	os.Mkdir(path, 0777)
	// // }
	// str := "ino" + tim + "_" + hashpk[0:16] + "_" + PackageName + ".txt"
	// ioutil.WriteFile(str, byteData, 0644)

	// // file, err1 := os.Open(path + "/" + str)
	// file, err1 := os.Open(str)
	// defer file.Close()
	// if err1 != nil {
	// 	fmt.Println("error2", err)
	// 	return objTCP
	// }
	// fileInfo, err := file.Stat()
	// if err != nil {
	// 	fmt.Println(err)
	// 	return objTCP
	// }

	// fileSize := FillString(strconv.FormatInt(fileInfo.Size(), 10), 10)
	// conn.Write([]byte(fileSize))
	// fileName := FillString(fileInfo.Name(), 128)
	// conn.Write([]byte(fileName))
	// // fmt.Println("Start sending file!", fileName, " ", fileSize)
	// sendBuffer := make([]byte, BUFFERSIZE)
	// for {
	// 	_, err = file.Read(sendBuffer)
	// 	if err == io.EOF {
	// 		break
	// 	}
	// 	conn.Write(sendBuffer)
	// }

	// conn.Write([]byte(FillString(strconv.Itoa(len(byteData)), 64)))
	// sendBuffer := make([]byte, BUFFERSIZE)
	// for index := 0; index <= len(byteData); index = index + BUFFERSIZE {
	// 	if index+BUFFERSIZE >= len(byteData) {
	// 		sendBuffer = byteData[index:len(byteData)]
	// 	} else {
	// 		sendBuffer = byteData[index : index+BUFFERSIZE]
	// 	}
	// 	conn.Write(sendBuffer)
	// }

	// if len(string(byteData))%256 == 0 {
	// 	fmt.Fprintf(conn, string(byteData)+" ")

	// } else {
	// 	fmt.Fprintf(conn, string(byteData))

	// }
	// conn.Write(byteData)
	// reqBodyBytes := new(bytes.Buffer)
	// json.NewEncoder(reqBodyBytes).Encode(objTCP)
	// conn.Write(reqBodyBytes.Bytes())
	// }
	return objTCP
}

func BoardcastingTokenImgUDP(obj string, Method, PackageName string) {
	// if PackageName == "transaction" {
	// }
	for _, validatorObj := range validator.ValidatorsLstObj {
		if !validatorObj.ValidatorRemove {
			if validatorObj.ValidatorIP == validator.CurrentValidator.ValidatorIP {

				SendTokenImg(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validator.CurrentValidator.ValidatorSoketIP)
			} else {

				SendTokenImg(obj, validatorObj.ValidatorPublicKey, Method, PackageName, validatorObj.ValidatorSoketIP)
			}
		}
	}
}
func FillString(retunString string, toLength int) string {
	for {
		lengtString := len(retunString)
		if lengtString < toLength {
			retunString = retunString + ":"
			continue
		}
		break
	}
	return retunString
}
