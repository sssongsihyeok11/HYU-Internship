
#include "openfhe.h"
#include <vector>
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
    //parameters.SetBatchSize(8);
    parameters.SetRingDim(16384);


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    return cc;
}
Ciphertext<DCRTPoly> compute_power(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &input, size_t degree){
    if(degree == 1) return input;

    size_t left_power = degree/2;

    Ciphertext<DCRTPoly> left = compute_power(cc, input, left_power);
    Ciphertext<DCRTPoly> right = compute_power(cc, input, degree - left_power);

    return cc->EvalMult(left, right);
}

std::vector<Ciphertext<DCRTPoly>> compute_powers(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> &input,  size_t len, size_t giant_step){
    size_t vector_len = (len - 1)/giant_step;

    std::vector<Ciphertext<DCRTPoly>> powers;
    Ciphertext<DCRTPoly> g = compute_power(cc, input, giant_step);
    for(size_t i = 0; i < vector_len; i++){
        if(i == 0) powers.push_back(g);
        else{
            powers.push_back(cc->EvalMult(g, powers[i - 1]));
        }
    }

    return powers;
}

Ciphertext<DCRTPoly> honor_method(CryptoContext<DCRTPoly> cc, int start, int end, std::vector<double> coefficient, 
                                Ciphertext<DCRTPoly> &input){
    Ciphertext<DCRTPoly> res = cc->EvalMult(input, coefficient[end]);

    for(int idx = end; idx > start; idx--){
        if(idx != end) res = cc->EvalMult(res, input);
        res = cc->EvalAdd(res, coefficient[idx - 1]);
    }

    return res;
}
Ciphertext<DCRTPoly> paterson_stock_meyer_recursive(CryptoContext<DCRTPoly> cc, int start, int end, int baby_step,
                                                    std::vector<double> coefficient, Ciphertext<DCRTPoly> &input, Ciphertext<DCRTPoly> &power){
    Ciphertext<DCRTPoly> res;

    return res;
}


Ciphertext<DCRTPoly> paterson_stock_meyer_linear(CryptoContext<DCRTPoly> cc, size_t start, size_t end, size_t baby_step,
                                                 std::vector<double> coefficient, Ciphertext<DCRTPoly> &input, std::vector<Ciphertext<DCRTPoly>> powers){
    Ciphertext<DCRTPoly> res;

    return res;
}
    
int main() {
    
    CryptoContext<DCRTPoly> cc = generate_params();
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> input({0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8});

    size_t encodedLength = input.size();

    std::vector<double> coefficients({1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1}); //1 + x^3 + x^6 + x^10 + x^11 +  x^14 + x^15

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

    Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    size_t giant_step = std::ceil(std::sqrt(static_cast<double>(coefficients.size())));
    size_t baby_step = coefficients.size() / giant_step;
    Ciphertext<DCRTPoly> power = compute_power(cc, ciphertext, giant_step);
    std::vector<Ciphertext<DCRTPoly>> powers = compute_powers(cc, ciphertext, coefficients.size(), giant_step);

    printf("===============================================\n start paterson stock-meyer using recursive\n\n");
    
    Ciphertext<DCRTPoly> recursive_result = paterson_stock_meyer_recursive(cc, 0, coefficients.size() - 1, baby_step, coefficients, ciphertext, power);

    Plaintext plaintextDec_recursive;

    cc->Decrypt(keyPair.secretKey, recursive_result, &plaintextDec_recursive);

    plaintextDec_recursive->SetLength(encodedLength);
    std::cout << std::setprecision(15) << std::endl;
    std::cout << plaintextDec_recursive << std::endl;

    printf("===============================================\n start paterson stock-meyer using linear\n\n");

    auto linear_result = paterson_stock_meyer_linear(cc, 0, coefficients.size(), baby_step, coefficients, ciphertext, powers);
    Plaintext plaintextDec_linear;

    cc->Decrypt(keyPair.secretKey, linear_result, &plaintextDec_linear);

    plaintextDec_linear->SetLength(encodedLength);
    std::cout << plaintextDec_linear << std::endl;


    return 0;
}
