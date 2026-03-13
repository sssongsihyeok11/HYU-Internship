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
    for idx in range(len(u_vector)):
        rotated_ciphertext = cc.EvalRotate(ciphertext, rotate_list[idx])
        if res is None:
            res = cc.EvalMult(rotated_ciphertext, u_vector[idx])
        else:
            res = cc.EvalAdd(res, cc.EvalMult(rotated_ciphertext, u_vector[idx]))
    return res


def sigma(cc, d):
    row_vector = []
    len = d*d
    for k in range(-d + 1, d):
        u_sigma_vector = [0.0] * len

        for idx in range(len):
            if k >= 0:
                if idx - d*k >= 0 and idx - d*k < d - k:
                    u_sigma_vector[idx] = 1.0
            else:
                if idx - (d + k)*d >= -k and idx - (d + k)*d < d:
                    u_sigma_vector[idx] = 1.0

        row_vector.append(cc.MakeCKKSPackedPlaintext(u_sigma_vector))
    return row_vector

def tau(cc, d):
    column_vector = []
    len = d*d
    for i in range(0, d):
        u_tau_vector = [0.0] * len
        for k in range(0, d):
            u_tau_vector[i + k*d] = 1.0
        column_vector.append(cc.MakeCKKSPackedPlaintext(u_tau_vector))
    return column_vector

def v(cc, d):
    v_vector = []
    len = d*d
    for k in range(-d + 1, 0):
        tmp = []
        v_k_vector = [0.0] * len
        remain = [0.0] * len
        masking = [1.0]*len
        for idx in range(len):
            mod_l = idx % d
            if abs(k) <= mod_l and mod_l < d :
                v_k_vector[idx] = 1.0
            
            remain[idx] = masking[idx] - v_k_vector[idx]
        tmp.append(cc.MakeCKKSPackedPlaintext(v_k_vector))
        tmp.append(cc.MakeCKKSPackedPlaintext(remain))

        v_vector.append(tmp)
    return v_vector

def w(cc, d):
    w_vector = []
    len = d*d
    for i in range(1, d):
        w_tmp = []
        w_k_vector = [1.0] * len

        w_tmp.append(cc.MakeCKKSPackedPlaintext(w_k_vector))
        w_vector.append(w_tmp)

    return w_vector

def step1(cc, ciphertext, vec, idx):
    return LinearTransformation(cc, ciphertext, vec, idx)

def step2(cc, A, B, v_vec, w_vec, idx_v, idx_w, d):
    for i in range(d - 1):
        A.append(LinearTransformation(cc, A[0], v_vec[i], idx_v[i]))
        B.append(LinearTransformation(cc, B[0], w_vec[i], idx_w[i]))

def step3(cc, A, B):
    res = None
    for i in range(len(A)):
        if res is None:
            res = cc.EvalMult(A[i], B[i])
        else:
            res = cc.EvalAdd(res, cc.EvalMult(A[i], B[i]))
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
