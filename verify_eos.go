package mykeyverify

import (
	"github.com/eoscanada/eos-go/ecc"
	"log"
	"crypto/sha256"
	"net/http"
	"encoding/json"
	"bytes"
	"errors"
)

var (
	eosNodeGetTableRowsUrl = "https://eos.mykey.tech/v1/chain/get_table_rows"
	requestKeyDataJson = `{ "json": true, "code": "mykeymanager", "scope": "mykeydoctest", "table": "keydata", "limit": 4 }`
	signingKeyIndex = 3
)

func VerifyEosSignature(unsignedData, signature, signingKey string)  {
	unsignedDataHashBytes := sigDigest([]byte(unsignedData))

	eosPubKey, err := ecc.NewPublicKey(signingKey)
	if err != nil {
		log.Println("in VerifyEosSignature signing key format error.")
		return
	}

	signatureObj, err := ecc.NewSignature(signature)
	if err != nil {
		log.Println("in VerifyEosSignature signature format error.")
		return
	}

	verifyResult := signatureObj.Verify(unsignedDataHashBytes, eosPubKey)
	log.Println("in VerifyEosSignature verify result:", verifyResult)
}

// 链上查询签名公钥及状态
func getEosSigningKeyAndStatus() (signingKey string, err error) {
	// 1. 获取用户账户的第3个操作密钥
	eosKeyData, err := requestTableRows(requestKeyDataJson)
	if err != nil {
		return "", err
	}
	if len(eosKeyData) != 4 {
		return "", err
	}
	// 2. 获取用户账户的第3个操作密钥的状态， 正常是0， 冻结是1
	signingKeyStatus := eosKeyData[signingKeyIndex].Key.Status
	if signingKeyStatus == 1 {
		return "", errors.New("key had been freezed.")
	}
	return eosKeyData[signingKeyIndex].Key.PubKey, nil
}

func requestTableRows(requestJson string) ([]EosTableRow, error) {
	req, err := http.NewRequest("POST", eosNodeGetTableRowsUrl, bytes.NewBuffer([]byte(requestJson)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var eosTableRows EosTableRows
	err = json.NewDecoder(resp.Body).Decode(&eosTableRows)
	if err != nil {
		return nil, err
	}
	if eosTableRows.Rows == nil || len(eosTableRows.Rows) == 0 {
		return nil, errors.New("can not find.")
	}

	return eosTableRows.Rows, nil
}

func sigDigest(payload []byte) []byte {
	h := sha256.New()
	//_, _ = h.Write(chainID)
	_, _ = h.Write(payload)
	return h.Sum(nil)
}

type EosTableRows struct {
	Rows []EosTableRow `json:"rows"`
}

type EosTableRow struct {
	Index int `json:"index"`
	Key EosTableRowKey `json:"key"`
}
type EosTableRowKey struct {
	PubKey string `json:"pubkey"`
	Status int `json:"status"`
	Nonce int `json:"nonce"`
}
