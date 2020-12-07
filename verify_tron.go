package mykeyverify

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"fmt"
	"github.com/eoscanada/eos-go/btcsuite/btcutil/base58"
	"crypto/sha256"
	"errors"
	"net/http"
	"bytes"
	"encoding/json"
	"strconv"
)
var (
	signTronFormat = "\x19TRON Signed Message:\n%d%s"
	tronNodeMethodCallUrl = "https://api.trongrid.io/wallet/triggerconstantcontract"
	tronAddressBase58 = "TSE3pCxRmSr7bPqk2qvQVFp2tah7LkyqeF"
	OwnerAddress = "410000000000000000000000000000000000000000"
	tronAccountContract = "41999d6a9d0bf917a9086e9c517165e0301c73ef81"
	keyDataFunctionSelector = "getKeyData(address,uint256)"
)

func VerifyTronSignature(unsignedData, signature, signingKeyBase58 string)  {
	signingKeyHex, err := getTRONAddressByBase58(signingKeyBase58)
	if err != nil {
		log.Println("in VerifyTronSignature getTRONAddressByBase58 error:", err.Error())
		return
	}
	unsignedDataHashByte := crypto.Keccak256Hash(common.FromHex(unsignedData)).Bytes()

	signingKeyAddr := common.HexToAddress(signingKeyHex)

	signatureBytes := common.FromHex(signature)
	if signatureBytes[64] != 1 && signatureBytes[64] != 0 && signatureBytes[64] != 27 && signatureBytes[64] != 28 {
		log.Println("in VerifyEthSignature decode error.")
		return
	}

	if signatureBytes[64] != 1 && signatureBytes[64] != 0 {
		signatureBytes[64] -= 27
	}
	pubKey, err := crypto.SigToPub(createTronSignHash(unsignedDataHashByte), signatureBytes)
	if err != nil {
		log.Println("in VerifyEthSignature crypto.SigToPub error:", err.Error())
		return
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	log.Println("in VerifyEthSignature verify result:", (signingKeyAddr == recoveredAddr))
}

// 链上查询签名公钥及状态
func getTronSigningKeyAndStatus() (signingKeyBase58Address string, err error) {
	// {"owner_address":"410000000000000000000000000000000000000000","contract_address":"41999d6a9d0bf917a9086e9c517165e0301c73ef81","function_selector":"getKeyData(address,uint256)","parameter":"000000000000000000000000b250953cc9a451034fec4aa3845a72a28cd7f9f10000000000000000000000000000000000000000000000000000000000000003"}
	tronAddress, err := getTRONAddressByBase58(tronAddressBase58)
	if err != nil {
		log.Println("in getTronSigningKeyAndStatus getTRONAddressByBase58 err:", err.Error())
		return "", err
	}
	keyDataRequest := &TronMethodCall{
		OwnerAddress: OwnerAddress,
		ContractAddress: tronAccountContract,
		FunctionSelector: keyDataFunctionSelector,
		Parameter: getParameterAddressData(tronAddress) + getParameterNormalData(strconv.FormatInt(int64(signingKeyIndex), 10)),
	}
	keyDataRequestJson, err := json.Marshal(keyDataRequest)
	if err != nil {
		log.Println("in getTronSigningKeyAndStatus Marshal err:", err.Error())
		return "", err
	}
	keyDataResult := &TronMethodCallResult{}
	err = requestContractMethod(string(keyDataRequestJson), keyDataResult)
	if err != nil {
		log.Println("in getTronSigningKeyAndStatus requestContractMethod err:", err.Error())
		return "", err
	}
	if keyDataResult.ConstantResult == nil || len(keyDataResult.ConstantResult) != 1 {
		log.Println("in getTronSigningKeyAndStatus can not find key data.")
		return "", errors.New("can not find key data.")
	}
	normalAddr := common.HexToAddress(keyDataResult.ConstantResult[0]).String()
	signingKeyAddress := "41" + normalAddr[2:]
	signingKeyBase58Address, err = getTRONBase58ByAddress(signingKeyAddress)
	if err != nil {
		log.Println("in getTronSigningKeyAndStatus getTRONBase58ByAddress err:", err.Error())
		return "", err
	}
	return signingKeyBase58Address, nil
}

func getParameterAddressData(tronAddress string) string {
	paramBytes := common.FromHex(tronAddress)
	return common.Bytes2Hex(common.LeftPadBytes(paramBytes[1:], 32))
}

func getParameterNormalData(param string) string {
	paramBytes := common.FromHex(param)
	return common.Bytes2Hex(common.LeftPadBytes(paramBytes, 32))
}

func requestContractMethod(requestJson string, replay interface{}) (error) {
	log.Println("requestJson:", requestJson)
	req, err := http.NewRequest("POST", tronNodeMethodCallUrl, bytes.NewBuffer([]byte(requestJson)))
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

	err = json.NewDecoder(resp.Body).Decode(&replay)
	if err != nil {
		return err
	}

	return nil
}

func getTRONBase58ByAddress(address string) (string, error) {
	addressBytes := common.FromHex(address)
	sum := checkSum(addressBytes)
	newAddressBytes := append(addressBytes, sum[:4]...)
	return base58.Encode(newAddressBytes), nil
}

func getTRONAddressByBase58(base58Address string) (string, error) {
	if !checkTRONBase58Address(base58Address) {
		return "", errors.New("in getTRONAddressByBase58 check tron base 58 address error.")
	}
	base58AddressBytes := base58.Decode(base58Address)
	addressBytes := base58AddressBytes[ : len(base58AddressBytes) - 4]
	return common.Bytes2Hex(addressBytes), nil
}

// must start with 0x
func checkTRONBase58Address(base58Address string) bool {
	if base58Address == "" || base58Address[0] != 'T' || len(base58Address) != 34 {
		log.Println("in CheckTRONAddress address is not start with T.")
		return false
	}
	// 校验是否是base58编码
	_, _, err := base58.CheckDecode(base58Address)
	if err != nil {
		log.Println("in CheckTRONAddress CheckDecode error:", err.Error())
		return false
	}

	base58AddressBytes := base58.Decode(base58Address)

	// 检测TRON地址正确性, base58AddressBytes后4个byte是地址两次sha256之后的前4个byte
	shaSuffixBytes := base58AddressBytes[len(base58AddressBytes) - 4 : ]
	addressBytes := base58AddressBytes[ : len(base58AddressBytes) - 4]

	sum := checkSum(addressBytes)

	if common.Bytes2Hex(sum[:4]) == common.Bytes2Hex(shaSuffixBytes) {
		return true
	}
	return false
}

// 待签名数据生成符合格式的hash
func createTronSignHash(data []byte) []byte {
	msg := fmt.Sprintf(signTronFormat, len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func checkSum(b []byte) []byte {
	sh1, sh2 := sha256.New(), sha256.New()
	sh1.Write(b)
	sh2.Write(sh1.Sum(nil))
	return sh2.Sum(nil)
}
// {"owner_address":"410000000000000000000000000000000000000000","contract_address":"41999d6a9d0bf917a9086e9c517165e0301c73ef81","function_selector":"getKeyData(address,uint256)","parameter":"000000000000000000000000b250953cc9a451034fec4aa3845a72a28cd7f9f10000000000000000000000000000000000000000000000000000000000000003"}

type TronMethodCall struct {
	OwnerAddress string `json:"owner_address"`
	ContractAddress string `json:"contract_address"`
	FunctionSelector string `json:"function_selector"`
	Parameter string `json:"parameter"`
}

type TronMethodCallResult struct {
	ConstantResult []string `json:"constant_result"`
}