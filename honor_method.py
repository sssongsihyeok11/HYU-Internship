from openfhe import *
import time


def gen_context():
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(6)
    parameters.SetScalingModSize(50)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(16384)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    return cc

def honors_method(cc, start, end, coefficient, x):

    res = cc.EvalMult(x, coefficient[end])
    for i in range(end, start, -1):
        if i!= end :
            res = cc.EvalMult(res, x)
        res = cc.EvalAdd(res, coefficient[i - 1])

    return res

def main():

    print("======EXAMPLE FOR Honor Method========")

    cc = gen_context()
    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)

    input = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    
    encoded_length = len(input)
    coefficients1 = [1.0, 1.0, 1.0, 1.0, 1.0]
    plaintext1 = cc.MakeCKKSPackedPlaintext(input)

    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext1)

    result = honors_method(cc, 0, len(coefficients1) - 1, coefficients1, ciphertext)
    plaintext_dec = cc.Decrypt(result, key_pair.secretKey)

    plaintext_dec.SetLength(encoded_length)


    print("\n Original Plaintext #1: \n")
    print(plaintext1)

    print(f"\n Result of evaluating a polynomial with coefficients {coefficients1}: \n")
    print(plaintext_dec)

if __name__ == '__main__':
    main() 
