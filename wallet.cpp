#include <iostream>
#include <fstream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <cryptopp/keccak.h>
#include <string>
#include <vector>
#include <random>

std::vector<std::string> getDictionary(const std::string& dict_path);
std::vector<unsigned char> getPrivateKey();
std::string derivePublicKey(std::vector<unsigned char> private_key);
std::vector<unsigned char> getAccountAddress(std::string derived_key);

// Creates the private-public key pairs for the ETH account
int main() {
  std::vector<unsigned char> key =  getPrivateKey();
  std::string public_key = derivePublicKey(key);
  std::vector<unsigned char> address = getAccountAddress(public_key);
  printf("ETH address: 0x");
  for (auto byte : address) {
    printf("%02x", byte);
  }
  printf("\n");
  return 0;
}

std::vector<std::string> getDictionary(const std::string& dict_path) {
  std::ifstream file(dict_path);
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(file, line)) {
      lines.push_back(line);
  }
  return lines;
}

std::vector<unsigned char> getPrivateKey() {
  std::vector<std::string> dict = getDictionary("/home/eth-wallet/data/words.txt");
  std::string mnemonic = "";
  for (std::size_t index=0; index<12; index++) {
    mnemonic += dict[rand()%2049];
  }
  std::vector<unsigned char> key(32);
  RAND_seed(mnemonic.c_str(), mnemonic.size());
  RAND_bytes(key.data(), key.size());
  return key;
}

std::string derivePublicKey(std::vector<unsigned char> private_key) {
  EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
  BIGNUM *priv_key_bn = BN_new();
  BN_bin2bn(private_key.data(), private_key.size(), priv_key_bn);
  EC_KEY_set_private_key(key, priv_key_bn);
  EC_POINT *pub_key_point = EC_POINT_new(EC_KEY_get0_group(key));
  EC_POINT_mul(EC_KEY_get0_group(key), pub_key_point, priv_key_bn, NULL, NULL, NULL);
  EC_KEY_set_public_key(key, pub_key_point);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
  std::string hex_pub_key = EC_POINT_point2hex(EC_KEY_get0_group(key), pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
  EC_POINT_free(pub_key_point);
  BN_free(priv_key_bn);
  EC_KEY_free(key);
  return hex_pub_key;
}

std::vector<unsigned char> getAccountAddress(std::string derived_key) {
  CryptoPP::Keccak_256 hash;
  CryptoPP::byte digest[CryptoPP::Keccak_256::DIGESTSIZE];
  hash.CalculateDigest(digest, (CryptoPP::byte*)derived_key.c_str(), derived_key.length());
  // Get the last 20 bytes of the hash
  std::vector<unsigned char> address(digest + 12, digest + 32);
  return address;
}