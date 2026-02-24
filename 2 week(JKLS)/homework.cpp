#include "openfhe.h"
#include <vector>
#include <math.h>
using namespace lbcrypto;

CryptoContext<DCRTPoly> generate_params(){
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    usint firstMod = 60;

    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(40);
    parameters.SetFirstModSize(firstMod);
    parameters.SetBatchSize(16);
    parameters.SetRingDim(16384);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    return cc;
}

void KeyGeneration(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> secretKey, int d, 
                  std::vector<int32_t> &indexList_Sigma, std::vector<int32_t> &indexList_Tau, 
                  std::vector<std::vector<int32_t>>&indexList_V, std::vector<std::vector<int32_t>> &indexList_W){
   
    for(int idx = -d + 1; idx < d; idx++){
        indexList_Sigma.push_back(idx);
    }

    for(int idx = 0; idx < d; idx++){
        indexList_Tau.push_back(d*idx);
    }

    for(int idx = -d + 1; idx < 0; idx++){
        if(idx == 0) continue;
        std::vector<int32_t> v_idx;
        v_idx.push_back(idx);
        v_idx.push_back(idx + d);
        indexList_V.push_back(v_idx);
    }

    for(int idx = 1; idx < d; idx++){
        std::vector<int32_t> w_idx;
        w_idx.push_back(d*idx);
        indexList_W.push_back(w_idx);
    }
    cc->EvalMultKeyGen(secretKey);
    cc->EvalRotateKeyGen(secretKey, indexList_Sigma);
    cc->EvalRotateKeyGen(secretKey, indexList_Tau);
}


Ciphertext<DCRTPoly> LinearTransformation(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> m, 
                                          std::vector<Plaintext> u_vector, std::vector<int32_t> rotate_list){
    Ciphertext<DCRTPoly> result;

    return result;
}

std::vector<Plaintext> sigma(CryptoContext<DCRTPoly> cc, int d){
    std::vector<Plaintext> row_vector;

    return row_vector;
}

std::vector<Plaintext> tau(CryptoContext<DCRTPoly> cc, int d){
    std::vector<Plaintext> column_vector;

    return column_vector;
}

std::vector<std::vector<Plaintext>> v(CryptoContext<DCRTPoly> cc, int d){
    std::vector<std::vector<Plaintext>> v_vector;

    return v_vector;
}

std::vector<std::vector<Plaintext>> w(CryptoContext<DCRTPoly> cc, int d){
    std::vector<std::vector<Plaintext>> w_vector;

    return w_vector;
}

Ciphertext<DCRTPoly> step1(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &ciphertext, std::vector<Plaintext> &vec, std::vector<int32_t> &idx){
    return LinearTransformation(cc, ciphertext, vec, idx);
}

void step2(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> &A, std::vector<Ciphertext<DCRTPoly>> &B, 
           std::vector<std::vector<Plaintext>>& v_vec, std::vector<std::vector<Plaintext>>& w_vec, 
           std::vector<std::vector<int32_t>> &idx_v, std::vector<std::vector<int32_t>> &idx_w, int d){
    
    for(int i = 0; i < d - 1; i++){
        A.push_back(LinearTransformation(cc, A[0], v_vec[i], idx_v[i]));
        B.push_back(LinearTransformation(cc, B[0], w_vec[i], idx_w[i]));
    }
}

Ciphertext<DCRTPoly> step3(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> &A, std::vector<Ciphertext<DCRTPoly>> &B){
    Ciphertext<DCRTPoly> res;

    return res;
}

Ciphertext<DCRTPoly> Matrix_Multiplication(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &A, Ciphertext<DCRTPoly> &B, 
                                           std::vector<int32_t> &idx_sigma, std::vector<int32_t> &idx_tau,
                                           std::vector<std::vector<int32_t>> &idx_v, std::vector<std::vector<int32_t>> &idx_w, int d){

    std::vector<Plaintext> sigma_vec = sigma(cc , d);
    std::vector<Plaintext> tau_vec = tau(cc, d);
    std::vector<std::vector<Plaintext>> v_vec = v(cc, d);
    std::vector<std::vector<Plaintext>> w_vec = w(cc, d);

    std::vector<Ciphertext<DCRTPoly>> A_vec;


    std::vector<Ciphertext<DCRTPoly>> B_vec;
    A_vec.push_back(step1(cc, A, sigma_vec, idx_sigma));
    B_vec.push_back(step1(cc, B, tau_vec, idx_tau));

    step2(cc, A_vec, B_vec, v_vec, w_vec, idx_v, idx_w, d);
    
    Ciphertext<DCRTPoly> res = step3(cc, A_vec, B_vec);

    return res;
}


int main() {
    
    CryptoContext<DCRTPoly> cc = generate_params();

    auto keyPair = cc->KeyGen();

    int d = 4;
    std::vector<int32_t> idx_sigma;
    std::vector<int32_t> idx_tau;
    std::vector<std::vector<int32_t>> idx_v;
    std::vector<std::vector<int32_t>> idx_w;
    KeyGeneration(cc, keyPair.secretKey, d, idx_sigma, idx_tau, idx_v, idx_w);
    
    std::vector<double> input({1.0, 1.0, 1.0, 1.0, 
                               2.0, 2.0, 2.0, 2.0, 
                               3.0, 3.0, 3.0, 3.0, 
                               4.0, 4.0, 4.0, 4.0});
    
    size_t encodedLength = input.size();
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    
    auto result = Matrix_Multiplication(cc, ciphertext, ciphertext, idx_sigma, idx_tau, idx_v, idx_w, d);

    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, result, &plaintextDec);

    plaintextDec->SetLength(encodedLength);
    std::cout << std::setprecision(15) << std::endl;
    std::cout << plaintextDec << std::endl;
    return 0;
}
