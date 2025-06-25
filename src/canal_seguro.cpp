#include <iostream>
#include <string>
#include "cryptlib.h"
#include "rsa.h"
#include "aes.h"
#include "modes.h"
#include "filters.h"
#include "osrng.h"
#include "files.h"
#include "hex.h"
#include "secblock.h" // Para SecByteBlock

int main() {
    std::cout << "--- Simulación de Creación de Canal Seguro (Cifrado Híbrido) ---" << std::endl;
    CryptoPP::AutoSeededRandomPool rng;

    // --- PREPARACIÓN ---
    CryptoPP::SecByteBlock aesKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(aesKey, aesKey.size());
    std::string encodedKey;
    CryptoPP::StringSource(aesKey, aesKey.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey)));
    std::cout << "\n[Pedrius] PASO 1: Clave de sesión AES generada -> " << encodedKey << std::endl;

    // --- PASO 2: Pedrius cifra la clave AES con la clave pública RSA del Gran Maestro ---
    std::string encryptedAesKey;
    try {
        // Carga la clave pública desde el archivo .der (esto ya funcionaba)
        CryptoPP::FileSource fs("claves/gm_publica.der", true);
        CryptoPP::RSAES_OAEP_SHA_Encryptor rsaEncryptor(fs);
        CryptoPP::StringSource(aesKey, aesKey.size(), true,
            new CryptoPP::PK_EncryptorFilter(rng, rsaEncryptor,
                new CryptoPP::StringSink(encryptedAesKey)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Pedrius al cifrar la clave de sesión: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "[Pedrius] PASO 2: Clave AES cifrada con RSA y lista para enviar." << std::endl;

    // --- PASO 3: El Gran Maestro descifra la clave AES con su clave privada RSA ---
    CryptoPP::SecByteBlock decryptedAesKey;
    try {
        CryptoPP::AutoSeededRandomPool prng;
        std::cout<<1<<std::endl;
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::FileSource fs("claves/gm_privada.der", true, new HexDecoder);
        std::cout<<2<<std::endl;
        privateKey.Load(fs);
        std::cout<<3<<std::endl;
        
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        std::cout<<4<<std::endl;

        std::ifstream file("test.txt");
        std::string cipherText = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        std::cout<<5<<std::endl;
        
        std::string recoveredText;
        std::cout<<6<<std::endl;
        
        CryptoPP::StringSource(cipherText, true,
            new CryptoPP::PK_DecryptorFilter(prng, decryptor, // Usamos prng y decryptor
                new CryptoPP::StringSink(recoveredText)   // El texto descifrado se guarda en recoveredText
            )
        );
        std::cout<<recoveredText<<std::endl;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Gran Maestro al descifrar la clave de sesión: " << e.what() << std::endl;
        return 1;
    }

    encodedKey.clear();
    CryptoPP::StringSource(decryptedAesKey, decryptedAesKey.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey)));
    std::cout << "\n[Gran Maestro] PASO 3: Clave de sesión AES descifrada -> " << encodedKey << std::endl;

    if (aesKey == decryptedAesKey) {
        std::cout << "[Sistema] ¡ÉXITO! Ambas partes ahora comparten la misma clave de sesión secreta." << std::endl;
    } else {
        std::cout << "[Sistema] ¡FALLO! Las claves no coinciden." << std::endl;
        return 1;
    }

    // --- PASO 4: El canal seguro está establecido. ---
    // (El resto del código para la comunicación AES)
    // ...
    return 0;
}
