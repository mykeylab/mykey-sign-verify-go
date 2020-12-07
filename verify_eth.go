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
	"github.com/neo4l/x/jsonrpc2"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
	err = jsonrpc2.Call(ethNodeUrl, "eth_call", params, &reply)
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
