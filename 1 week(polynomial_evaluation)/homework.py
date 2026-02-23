from openfhe import *
import math


def gen_context():
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(6)
    parameters.SetScalingModSize(50)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetRingDim(16384)
    parameters.SetSecurityLevel(HEStd_NotSet)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    return cc


def compute_power(cc, x, degree):
    if degree == 1 : return x

    left_degree = degree//2

    left_power = compute_power(cc, x, left_degree)
    right_power = compute_power(cc, x, degree - left_degree)

    return cc.EvalMult(left_power, right_power)

def compute_powers(cc, x, len, giant_step):
    powers = []
    powers_len = (len - 1) // giant_step

    g = compute_power(cc, x, giant_step)

    for i in range(powers_len):
        if i == 0:
            powers.append(g)
        else:
            powers.append(cc.EvalMult(powers[i - 1], g))

    return powers

def honors_method(cc, start, end, coefficient, x):

    res = cc.EvalMult(x, coefficient[end])
    for i in range(end, start, -1):
        if i!= end :
            res = cc.EvalMult(res, x)
        res = cc.EvalAdd(res, coefficient[i - 1])

    return res

def paterson_stock_meyer_recursive(cc, start, end, baby_step, coefficient, x, p):
    res = None

    return res


def paterson_stock_meyer_linear(cc, start, end, baby_step, coefficient, x, powers):
    res = None

    return res
def main():

    cc = gen_context()

    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)

    input_vec = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    encoded_length = len(input_vec)

    coefficients = [1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1] #1 + x^3 + x^6 + x^10 + x^11 +  x^14 + x^15

    plaintext = cc.MakeCKKSPackedPlaintext(input_vec)
    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext)

    giant_step = math.ceil(math.sqrt(len(coefficients)))
    baby_step = len(coefficients) // giant_step

    power = compute_power(cc, ciphertext, giant_step)

    powers = compute_powers(cc, ciphertext, len(coefficients), giant_step)

    print("===============================================")
    print("recursive method\n")

    recursive_result = paterson_stock_meyer_recursive(cc, 0, len(coefficients) - 1, baby_step, 
                                                      coefficients, ciphertext, power)

    plaintext_dec_recursive = cc.Decrypt(key_pair.secretKey, recursive_result)
    plaintext_dec_recursive.SetLength(encoded_length)

    print(plaintext_dec_recursive)

    print("\n===============================================")
    print("linear method\n")

    linear_result = paterson_stock_meyer_linear(cc, 0, len(coefficients), baby_step, 
                                                coefficients, ciphertext, powers)

    plaintext_dec_linear = cc.Decrypt(key_pair.secretKey, linear_result)
    plaintext_dec_linear.SetLength(encoded_length)

    print(plaintext_dec_linear)


if __name__ == '__main__':
    main()
