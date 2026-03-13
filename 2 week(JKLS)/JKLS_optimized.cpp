/*
JKLS optimized works only d = k^2
*/

#include "openfhe.h"
#include <vector>
#include <math.h>
#include <chrono>
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

void KeyGeneration_optimized(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> secretKey, int d, 
                  std::vector<int32_t> &baby_step_sigma, std::vector<int32_t> &giant_step_sigma, std::vector<int32_t> &single_rot_sigma,
                  std::vector<int32_t> &baby_step_tau, std::vector<int32_t> &giant_step_tau, 
                  std::vector<std::vector<int32_t>>&indexList_V, std::vector<std::vector<int32_t>> &indexList_W){

    
    for(int idx = -round(sqrt(d)) + 1; idx < round(sqrt(d)); idx++){
        int g_step = round(sqrt(d));

        giant_step_sigma.push_back(g_step*idx);
        if(idx >= 0){
            baby_step_sigma.push_back(idx);
        }
    }

    int32_t single_step_start = -d + 1;
    int num = 0;

    while(num != round(sqrt(d)) - 1){
        single_rot_sigma.push_back(single_step_start);
        single_step_start += 1;
        num += 1;
    }

    for(int idx = 0; idx < round(sqrt(d)); idx++){
        baby_step_tau.push_back(d*idx);
        giant_step_tau.push_back(d*round(sqrt(d)) * idx);
    }

    for(int idx = -d + 1; idx < 0; idx++){
        if(idx == 0) continue;
        std::vector<int32_t> v_idx;
        v_idx.push_back(idx);
        v_idx.push_back(idx + d);
        indexList_V.push_back(v_idx);
        cc->EvalRotateKeyGen(secretKey, v_idx);
    }

    for(int idx = 1; idx < d; idx++){
        std::vector<int32_t> w_idx;
        w_idx.push_back(d*idx);
        indexList_W.push_back(w_idx);
        cc->EvalRotateKeyGen(secretKey, w_idx);
    }
    cc->EvalMultKeyGen(secretKey);
    cc->EvalRotateKeyGen(secretKey, baby_step_sigma);
    cc->EvalRotateKeyGen(secretKey, giant_step_sigma);
    cc->EvalRotateKeyGen(secretKey, single_rot_sigma);
    cc->EvalRotateKeyGen(secretKey, baby_step_tau);
    cc->EvalRotateKeyGen(secretKey, giant_step_tau);
    
}

void debug(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &ct, PrivateKey<DCRTPoly> sk, size_t encodedLength){
    Plaintext plaintextDec;

    cc->Decrypt(sk, ct, &plaintextDec);

    plaintextDec->SetLength(encodedLength);
    std::cout << std::setprecision(15) << std::endl;
    std::cout << plaintextDec << std::endl;
}

Ciphertext<DCRTPoly> LinearTransformation(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> m, 
                                          std::vector<Plaintext> u_vector, std::vector<int32_t> rotate_list){

    Ciphertext<DCRTPoly> result = cc->EvalMult(cc->EvalRotate(m, rotate_list[0]), u_vector[0]);

    for(size_t i = 1; i < rotate_list.size(); i++){
        result = cc->EvalAdd(result, cc->EvalMult(cc->EvalRotate(m, rotate_list[i]), u_vector[i]));
    }
    return result;
}


Ciphertext<DCRTPoly> Rot_Sum(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> m, std::vector<int32_t> rotate_list){
    Ciphertext<DCRTPoly> result = cc->EvalRotate(m, rotate_list[0]);

    for(size_t i = 1; i < rotate_list.size(); i++){
        result = cc->EvalAdd(result, cc->EvalRotate(m, rotate_list[i]));
    }
    return result;
}

Ciphertext<DCRTPoly> baby_step(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> &A, std::vector<Plaintext> &plain_unit_vec){
    auto res = cc->EvalMult(A[0], plain_unit_vec[0]);
    for(size_t i = 1; i < A.size(); i++){
        res = cc->EvalAdd(res, cc->EvalMult(A[i], plain_unit_vec[i]));
    }
    return res;
}

void baby_step_giant_step(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> A, std::vector<std::vector<Plaintext>> plain_vec, 
                          std::vector<int32_t> &giant_step, Ciphertext<DCRTPoly> &res){
    res = cc->EvalRotate(baby_step(cc, A, plain_vec[0]), giant_step[0]);
    for(size_t i = 1; i < giant_step.size(); i++){
        auto tmp = cc->EvalRotate(baby_step(cc, A, plain_vec[i]), giant_step[i]);
        res = cc->EvalAdd(res, tmp);    
    }
}

void set_u_vector(std::vector<double> &u_sigma_vector, int d, int k){
    for(int idx = 0; idx < static_cast<int>(u_sigma_vector.size()); idx++){
        if(k >= 0){
            if(idx - d*k >= 0 && idx - d*k < d - k) u_sigma_vector[idx] = 1.0;
        }
        else{
            if(idx - (d + k)*d >= -k && idx - (d + k)*d < d) u_sigma_vector[idx] = 1.0;
        } 
    }
}

void set_tau_vector(std::vector<double> &u_tau_vector, int d, int k){
    for(int t = 0; t < d; t++){
        u_tau_vector[t*d + k] = 1.0;
    }
}
std::vector<Ciphertext<DCRTPoly>> precompute_rotate(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &A, std::vector<int32_t> &baby_step){

    std::vector<Ciphertext<DCRTPoly>> res;
    for(size_t i = 0; i < baby_step.size(); i++){
        int32_t rot_size = baby_step[i];
        res.push_back(cc->EvalRotate(A, rot_size));
    }

    return res;
}


void sigma_optimized(CryptoContext<DCRTPoly> cc, std::vector<std::vector<Plaintext>> &precomputed_row_vector, std::vector<Plaintext> &single_rot_vector, int d){
    int len = d*d;
    int k = -d + 1;
    int precomputed_row_vector_size = 2*round(sqrt(d)) - 1;
    for(int sz = 0; sz < round(sqrt(d)) - 1; sz++){
        std::vector<double> u_sigma_vector(len, 0.0);
        set_u_vector(u_sigma_vector, d, k);

        if(single_rot_vector.empty() || single_rot_vector.size() < round(sqrt(d)) - 1){
            auto pt = cc->MakeCKKSPackedPlaintext(u_sigma_vector);
            single_rot_vector.push_back(pt);
            k += 1;
        }
    }

    int precomputed_row_vector_unit_vector_size = round(sqrt(d));
    for(int idx = 0; idx < precomputed_row_vector_size; idx++){
        int32_t plaintext_rot_size = (-round(sqrt(d)))*(-round(sqrt(d)) + idx + 1);
        std::vector<Plaintext> tmp;
        for(int k_ = k; k_ < k + precomputed_row_vector_unit_vector_size; k_++){
            std::vector<double> u_sigma_vector(len, 0.0);
            set_u_vector(u_sigma_vector, d, k_);
            auto pt = cc->MakeCKKSPackedPlaintext(u_sigma_vector);
            tmp.push_back(cc->EvalRotate(pt, plaintext_rot_size));
        }
        precomputed_row_vector.push_back(tmp);
        k += precomputed_row_vector_unit_vector_size;
    }
}

std::vector<std::vector<Plaintext>> tau_optimized(CryptoContext<DCRTPoly> cc, int d){
    std::vector<std::vector<Plaintext>> column_vector;
    int vector_len = round(sqrt(d));
    int unit_vector_len = round(sqrt(d));
    int len = d*d;
    for(int i = 0; i < vector_len; i++){
        std::vector<Plaintext> unit_vector;
        for(int j = 0; j < unit_vector_len; j++){
            std::vector<double> u_tau_vector(len, 0.0);
            int k = round(sqrt(d))*i + j;

            set_tau_vector(u_tau_vector, d, k);
            
            unit_vector.push_back(cc->MakeCKKSPackedPlaintext(u_tau_vector));
        }
        column_vector.push_back(unit_vector);
    }

    return column_vector;
}

std::vector<Plaintext> v_optimized(CryptoContext<DCRTPoly> cc, int d){
    std::vector<Plaintext> v_vector;
    int len = d*d;
    for(int k = 1; k < d; k++){
        std::vector<double> v_k_vector(len, 0.0);
        for(int idx = 0; idx < len; idx++){
            int mod_l = idx % d;
            if(0 <= mod_l && mod_l < (d - k) ) v_k_vector[idx] = 1.0;
        }
        auto pt = cc->MakeCKKSPackedPlaintext(v_k_vector);
        v_vector.push_back(cc->EvalRotate(pt, -k));
    }

    return v_vector;
}

void step1_optimized(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &A, Ciphertext<DCRTPoly> &B,
            std::vector<std::vector<Plaintext>> precomputed_row_vector, std::vector<Plaintext> single_rot_sigma_plain, std::vector<std::vector<Plaintext>> precomputed_column_vector,
            std::vector<int32_t> baby_step_sigma, std::vector<int32_t> giant_step_sigma, std::vector<int32_t> single_rot_sigma,
            std::vector<int32_t> baby_step_tau, std::vector<int32_t> giant_step_tau, Ciphertext<DCRTPoly> &baby_step_giant_step_sigma, Ciphertext<DCRTPoly> &baby_step_giant_step_tau){

    std::vector<Ciphertext<DCRTPoly>> ciphertext_rotation_precomputed_sigma = precompute_rotate(cc, A, baby_step_sigma);
    std::vector<Ciphertext<DCRTPoly>> ciphertext_rotation_precomputed_tau = precompute_rotate(cc, B, baby_step_tau);
    auto single_sigma = LinearTransformation(cc, A, single_rot_sigma_plain, single_rot_sigma);
    
    baby_step_giant_step(cc, ciphertext_rotation_precomputed_sigma, precomputed_row_vector, giant_step_sigma, baby_step_giant_step_sigma);
    baby_step_giant_step(cc, ciphertext_rotation_precomputed_tau, precomputed_column_vector, giant_step_tau, baby_step_giant_step_tau);

    baby_step_giant_step_sigma = cc->EvalAdd(single_sigma, baby_step_giant_step_sigma);
}

Ciphertext<DCRTPoly> optimize_step2(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &A, Ciphertext<DCRTPoly> & reuse, std::vector<int32_t> &idx_v){
    auto partial1 = cc->EvalRotate(cc->EvalSub(A, reuse), idx_v[0]);
    auto partial2 = cc->EvalRotate(reuse, idx_v[1]);

    return cc->EvalAdd(partial1, partial2);
}
void step2_optimized(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> &A, std::vector<Ciphertext<DCRTPoly>> &B, 
           std::vector<Plaintext>& v_vec, std::vector<std::vector<int32_t>> &idx_v, 
           std::vector<std::vector<int32_t>> &idx_w, int d){
    
    for(int i = 0; i < d - 1; i++){
        auto reuse = cc->EvalMult(A[0], v_vec[i]);
        A.push_back(optimize_step2(cc, A[0], reuse, idx_v[i]));
        B.push_back(Rot_Sum(cc, B[0], idx_w[i]));
    }
}

Ciphertext<DCRTPoly> step3(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> &A, std::vector<Ciphertext<DCRTPoly>> &B){
    Ciphertext<DCRTPoly> res = cc->EvalMult(A[0], B[0]);

    for(size_t i = 1; i < A.size(); i++){
        res = cc->EvalAdd(res, cc->EvalMult(A[i], B[i]));
    }
    return res;
}


void Matrix_Multiplication_optimized(CryptoContext<DCRTPoly> cc){

    auto keyPair = cc->KeyGen();
    int d = 4;

    std::vector<std::vector<Plaintext>> precomputed_row_vector;

    std::vector<Plaintext> single_rot_sigma_plain;
    sigma_optimized(cc, precomputed_row_vector, single_rot_sigma_plain, d);
    std::vector<std::vector<Plaintext>> precomputed_column_vector = tau_optimized(cc, d);
    std::vector<Plaintext> v_vec = v_optimized(cc, d);
   
    std::vector<int32_t> baby_step_sigma, giant_step_sigma, single_rot_sigma;
    std::vector<int32_t> baby_step_tau, giant_step_tau;


    std::vector<std::vector<int32_t>> idx_v;
    std::vector<std::vector<int32_t>> idx_w;
    std::vector<Ciphertext<DCRTPoly>> A_vec;
    std::vector<Ciphertext<DCRTPoly>> B_vec;
    Ciphertext<DCRTPoly> baby_step_giant_step_sigma;
    Ciphertext<DCRTPoly> baby_step_giant_step_tau;

    KeyGeneration_optimized(cc, keyPair.secretKey, d, baby_step_sigma, giant_step_sigma, single_rot_sigma, baby_step_tau, giant_step_tau, idx_v, idx_w);
    
    std::vector<double> input({1.0, 1.0, 1.0, 1.0, 
                               2.0, 2.0, 2.0, 2.0, 
                               3.0, 3.0, 3.0, 3.0, 
                               4.0, 4.0, 4.0, 4.0});
    
    size_t encodedLength = input.size();
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    auto start = std::chrono::steady_clock::now();
    step1_optimized(cc, ciphertext, ciphertext, precomputed_row_vector, single_rot_sigma_plain, precomputed_column_vector,
          baby_step_sigma, giant_step_sigma, single_rot_sigma, baby_step_tau, giant_step_tau, baby_step_giant_step_sigma, baby_step_giant_step_tau);

    A_vec.push_back(baby_step_giant_step_sigma);
    B_vec.push_back(baby_step_giant_step_tau);

    step2_optimized(cc, A_vec, B_vec, v_vec, idx_v, idx_w, d);
    
    Ciphertext<DCRTPoly> res = step3(cc, A_vec, B_vec);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Elapsed time: " << elapsed.count() << "ms\n";

    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, res, &plaintextDec);

    plaintextDec->SetLength(encodedLength);
    std::cout << std::setprecision(15) << std::endl;
    std::cout << plaintextDec << std::endl;
}


int main() {
    
    CryptoContext<DCRTPoly> cc = generate_params();
    
    Matrix_Multiplication_optimized(cc);

    return 0;
}
