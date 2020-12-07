package mykeyverify

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"fmt"
	"log"
	"strings"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/math"
	"strconv"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"net/http"
	"bytes"
	"encoding/json"
	"math/rand"
	"io"
	"errors"
)

const (
	ethNodeUrl = "https://eth.mykey.tech"
	ethAddress = "0x3bB9E1783D5F60927eD6c3d0c32BfAD055A1b72f"
	ethAccountContract = "0xADc92d1fD878580579716d944eF3460E241604b7"
	signFormat = "\x19Ethereum Signed Message:\n%d%s"
	accountAbi = `[{"constant":true,"inputs":[{"name":"_account","type":"address"}],"name":"getOperationKeyCount","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"}],"name":"increaseKeyCount","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"}],"name":"getKeyData","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"},{"name":"_key","type":"address"}],"name":"setKeyData","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"}],"name":"getKeyStatus","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"},{"name":"_status","type":"uint256"}],"name":"setKeyStatus","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"}],"name":"getBackupAddress","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"}],"name":"getBackupEffectiveDate","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"}],"name":"getBackupExpiryDate","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"},{"name":"_backup","type":"address"},{"name":"_effective","type":"uint256"},{"name":"_expiry","type":"uint256"}],"name":"setBackup","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"},{"name":"_expiry","type":"uint256"}],"name":"setBackupExpiryDate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_index","type":"uint256"}],"name":"clearBackupData","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_actionId","type":"bytes4"}],"name":"getDelayDataHash","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"},{"name":"_actionId","type":"bytes4"}],"name":"getDelayDataDueTime","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_actionId","type":"bytes4"},{"name":"_hash","type":"bytes32"},{"name":"_dueTime","type":"uint256"}],"name":"setDelayData","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_actionId","type":"bytes4"}],"name":"clearDelayData","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_client","type":"address"},{"name":"_proposer","type":"address"},{"name":"_actionId","type":"bytes4"}],"name":"getProposalDataHash","outputs":[{"name":"","type":"bytes32"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_client","type":"address"},{"name":"_proposer","type":"address"},{"name":"_actionId","type":"bytes4"}],"name":"getProposalDataApproval","outputs":[{"name":"","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_client","type":"address"},{"name":"_proposer","type":"address"},{"name":"_actionId","type":"bytes4"},{"name":"_hash","type":"bytes32"},{"name":"_approvedBackup","type":"address"}],"name":"setProposalData","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_client","type":"address"},{"name":"_proposer","type":"address"},{"name":"_actionId","type":"bytes4"}],"name":"clearProposalData","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"},{"name":"_keys","type":"address[]"},{"name":"_backups","type":"address[]"}],"name":"initAccount","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]`
)

func VerifyEthSignature(unsignedData, signature, signingKey string)  {
	unsignedDataHashByte := crypto.Keccak256Hash(common.FromHex(unsignedData)).Bytes()

	signingKeyAddr := common.HexToAddress(signingKey)

	signatureBytes := common.FromHex(signature)
	if signatureBytes[64] != 1 && signatureBytes[64] != 0 && signatureBytes[64] != 27 && signatureBytes[64] != 28 {
		log.Println("in VerifyEthSignature decode error.")
		return
	}

	if signatureBytes[64] != 1 && signatureBytes[64] != 0 {
		signatureBytes[64] -= 27
	}
	pubKey, err := crypto.SigToPub(createSignHash(unsignedDataHashByte), signatureBytes)
	if err != nil {
		log.Println("in VerifyEthSignature crypto.SigToPub error:", err.Error())
		return
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	log.Println("in VerifyEthSignature verify result:", (signingKeyAddr == recoveredAddr))
}

// 链上查询签名公钥及状态
func getEthSigningKeyAndStatus() (signingKeyAddress string, err error) {
	// 1、解析abi，abi是对合约方法的参数返回值的定义，此定义可以用来序列化与反序列化数据
	abiObj, err := abi.JSON(strings.NewReader(accountAbi))
	if err != nil {
		log.Println("in getEthSigningKeyAndStatus abiJson err:", err.Error())
		return "", err
	}
	// 2、序列化合约方法getKeyData的数据，接口调用会用到
	requestDataByte, err := abiObj.Pack("getKeyData", common.HexToAddress(ethAddress), math.MustParseBig256(strconv.FormatInt(int64(signingKeyIndex), 10)))
	if err != nil {
		log.Println("in getEthSigningKeyAndStatus abiObj pack err:", err.Error())
		return "", err
	}
	// 3、调用eth_call方法来获取合约方法getKeyData的返回值
	reply := ""
	params := make([]interface{}, 2)
	ethCallRequest := &EthCallRequest{}
	ethCallRequest.To = ethAccountContract
	ethCallRequest.Data = hexutil.Encode(requestDataByte)
	params[0] = ethCallRequest
	params[1] = "latest"
	err = Call(ethNodeUrl, "eth_call", params, &reply)
	if err != nil {
		log.Println("in getEthSigningKeyAndStatus Call error:", err.Error())
		return "", err
	}
	return common.HexToAddress(reply).String(), nil
}

// 待签名数据生成符合格式的hash
func createSignHash(data []byte) []byte {
	msg := fmt.Sprintf(signFormat, len(data), data)
	return crypto.Keccak256([]byte(msg))
}

type EthCallRequest struct {
	To string `json:"to"`
	Data string `json:"data"`
}

func Call(url string, method string, params interface{}, reply interface{}) error {
	j, err := EncodeReqObj(method, params)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	//log.Printf("result.Body: %s", resp.Body)
	return DecodeResObj(resp.Body, &reply)
}

// EncodeReqObj encodes parameters for a JSON-RPC client request.
func EncodeReqObj(method string, args interface{}) ([]byte, error) {
	c := &ReqObj{
		Version: "2.0",
		Method:  method,
		Params:  args,
		Id:      uint64(rand.Int63()),
	}
	return json.Marshal(c)
}

// DecodeResObj decodes the response body of a client request into
// the interface reply.
func DecodeResObj(r io.Reader, reply interface{}) error {
	var c ResObj
	if err := json.NewDecoder(r).Decode(&c); err != nil {
		return err
	}
	if c.Error != nil {
		return errors.New("in DecodeResObj return error.")
	}
	if c.Result == nil {
		return errors.New("response body is null")
	}
	return json.Unmarshal(*c.Result, reply)
}

type ReqObj struct {
	// JSON-RPC protocol.
	Version string `json:"jsonrpc"`

	// A String containing the name of the method to be invoked.
	Method string `json:"method"`

	// Object to pass as request parameter to the method.
	Params interface{} `json:"params"`

	// The request id. This can be of any type. It is used to match the
	// response with the request that it is replying to.
	Id uint64 `json:"id"`
}
// ResObj represents a JSON-RPC response returned to a client.
type ResObj struct {
	Version string           `json:"jsonrpc"`
	Result  *json.RawMessage `json:"result"`
	Error   *json.RawMessage `json:"error"`
	Id      uint64           `json:"id"`
}

// JSON-RPC error object
type ErrorCode int

type Error struct {
	// A Number that indicates the error type that occurred.
	Code ErrorCode `json:"code"` /* required */

	// A String providing a short description of the error.
	// The message SHOULD be limited to a concise single sentence.
	Message string `json:"message"` /* required */

	// A Primitive or Structured value that contains additional information about the error.
	Data interface{} `json:"data"` /* optional */
}