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
    parameters.SetRingDim(16384);
    parameters.SetKeySwitchTechnique(HYBRID); 

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    return cc;
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

    std::vector<double> coefficient({1, 1, 1, 1, 1});

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    Ciphertext<DCRTPoly> powers;
    auto result = honor_method(cc, 0, coefficient.size() - 1, coefficient, ciphertext);

    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, result, &plaintextDec);

    plaintextDec->SetLength(encodedLength);
    std::cout << std::setprecision(15) << std::endl;
    std::cout << plaintextDec << std::endl;
    return 0;
}
