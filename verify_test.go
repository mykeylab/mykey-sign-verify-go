package mykeyverify

import (
	"testing"
	"log"
)

func TestVerifyEosSignature(t *testing.T) {
	signingKey, err := getEosSigningKeyAndStatus()
	if err != nil {
		log.Println("in TestVerifyEosSignature err:", err.Error())
		return
	}
	log.Println("signingKey:", signingKey)
	unsignedData := "1606900362mykeydocteste9467118-9321-4916-8153-4a5a9087e51emykeyE87E3CC788C44BB8544003AF6CEB62E8"
	signature := "SIG_K1_KcMxF6rNee2jsM9fge5CZWiENU4j6YLsHgKHD7n9TWvvhLSBtHE8rHV641sVdrw3JRcvCjBtGPRBHSBxzMubzw8DYVnk2e"
	//signingKey := "EOS6XmD7NK12LnmtXHtdnReTYbgRV1JPeo1M1BQvrHgnz6J1nNCFZ"
	VerifyEosSignature(unsignedData, signature, signingKey)
}

func TestVerifyEthSignature(t *testing.T) {
	signingKey, err := getEthSigningKeyAndStatus()
	if err != nil {
		log.Println("in TestVerifyEthSignature err:", err.Error())
		return
	}
	unsignedData := "3136303639303436383230783362423945313738334435463630393237654436633364306333324266414430353541316237326665393436373131382d393332312d343931362d383135332d3461356139303837653531656d796b65794538374533434337383843343442423835343430303341463643454236324538"
	signature := "0x53d86f27d725d3660f242cf0efc1f62aed8c805a39bf9783e2e7c1f65a81d94f775dbcb2e7268672dccbb68518bf5b9ba5f0ad5b2bf20ff4f8c9043f7c43d6651c"
	//signingKey := "0x37ac6c8229788643d62eF447eD988Ee7F00f8875"
	VerifyEthSignature(unsignedData, signature, signingKey)
}

func TestVerifyTronSignature(t *testing.T) {
	signingKey, err := getTronSigningKeyAndStatus()
	if err != nil {
		log.Println("in TestVerifyEthSignature err:", err.Error())
		return
	}
	unsignedData := "3136303639303439313754534533704378526d5372376250716b3271765156467032746168374c6b7971654665393436373131382d393332312d343931362d383135332d3461356139303837653531656d796b65794538374533434337383843343442423835343430303341463643454236324538"
	signature := "0x3e6540f8782f4890fadc4f6b9eef1fb8d1717e275f8c3c5ade2f3dd4edd1d0ae7e605047698d20071f89418698b7cfa42a2b5506699c7ee43ad20ba827d8492a1c"
	//signingKey := "TF3aiq4vjg3pvU4kfMy588YzjPsahKi7Pd"
	log.Println("signingKey:", signingKey)
	VerifyTronSignature(unsignedData, signature, signingKey)
}