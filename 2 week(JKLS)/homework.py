from openfhe import *
import math


def gen_context():
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(6)
    parameters.SetScalingModSize(50)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetRingDim(16384)
    parameters.SetBatchSize(16)
    parameters.SetSecurityLevel(HEStd_NotSet)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    return cc

def KeyGeneration(cc, secret_key, index_list_Sigma, index_list_Tau, index_list_V, index_list_W, d):
    for idx in range(-d + 1, d):
        index_list_Sigma.append(idx)

    for idx in range(0, d):
        index_list_Tau.append(d * idx)

    for idx in range(-d + 1, 0):
        if idx == 0:
            continue
        v_idx = []
        v_idx.append(idx)
        v_idx.append(idx + d)
        index_list_V.append(v_idx)

    for idx in range(1, d):
        w_idx = []
        w_idx.append(d * idx)
        index_list_W.append(w_idx)

    cc.EvalMultKeyGen(secret_key)
    cc.EvalRotateKeyGen(secret_key, index_list_Sigma)
    cc.EvalRotateKeyGen(secret_key, index_list_Tau)

def LinearTransformation(cc, ciphertext, u_vector, rotate_list):
    res = None

    return res


def sigma(cc, d):
    row_vector = []

    return row_vector

def tau(cc, d):
    column_vector = []

    return column_vector

def v(cc, d):
    v_vector = []

    return v_vector

def w(cc, d):
    w_vector = []


    return w_vector

def step1(cc, ciphertext, vec, idx):
    return LinearTransformation(cc, ciphertext, vec, idx)

def step2(cc, A, B, v_vec, w_vec, idx_v, idx_w, d):
    for i in range(d - 1):
        A.append(LinearTransformation(cc, A[0], v_vec[i], idx_v[i]))
        B.append(LinearTransformation(cc, B[0], w_vec[i], idx_w[i]))

def step3(cc, A, B):
    res = None

    return res

def Matrix_Multiplication(cc, A, B, idx_sigma, idx_tau, idx_v, idx_w, d):
    sigma_vec = sigma(cc, d)
    tau_vec = tau(cc, d)
    v_vec = v(cc, d)
    w_vec = w(cc, d)
    A_vec = []
    B_vec = []
    A_vec.append(step1(cc, A, sigma_vec, idx_sigma))
    B_vec.append(step1(cc, B, tau_vec, idx_tau))

    step2(cc, A_vec, B_vec, v_vec, w_vec, idx_v, idx_w, d)
    res = step3(cc, A_vec, B_vec)

    return res

def main():
    cc = gen_context()
    key_pair = cc.KeyGen()
    d = 4
    idx_sigma = []
    idx_tau = []
    idx_v = []
    idx_w = []
    KeyGeneration(cc, key_pair.secretKey, idx_sigma, idx_tau, idx_v, idx_w, d)
    input = [1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0, 3.0, 3.0, 3.0, 3.0, 4.0, 4.0, 4.0, 4.0]
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext)
    result = Matrix_Multiplication(cc, ciphertext, ciphertext, idx_sigma, idx_tau, idx_v, idx_w, d)
    plaintext_dec = cc.Decrypt(result, key_pair.secretKey)
    plaintext_dec.SetLength(len(input))
    
    print(plaintext_dec)

if __name__ == '__main__':
    main() 
