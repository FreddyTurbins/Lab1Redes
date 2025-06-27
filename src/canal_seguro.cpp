#include <iostream>
#include <string>
#include <fstream> // Required for file operations

// Crypto++ headers
#include "cryptlib.h"
#include "rsa.h"
#include "aes.h"
#include "modes.h" // For CBC_Mode
#include "filters.h"
#include "osrng.h" // For AutoSeededRandomPool
#include "files.h" // For FileSource
#include "hex.h"   // For HexEncoder (still useful for displaying keys)
#include "secblock.h" // For SecByteBlock

int main() {
    std::cout << "--- Simulación de Creación de Canal Seguro (Cifrado Híbrido) ---" << std::endl;
    CryptoPP::AutoSeededRandomPool rng; // Random number generator

    // --- PREPARACIÓN ---
    // Pedrius generates a symmetric AES session key
    CryptoPP::SecByteBlock aesKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(aesKey, aesKey.size());

    // Encode and display the generated AES key for verification
    std::string encodedKey;
    CryptoPP::StringSource(aesKey.data(), aesKey.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey))
    );
    std::cout << "\n[Pedrius] PASO 1: Clave de sesión AES generada -> " << encodedKey << std::endl;

    // --- PASO 2: Pedrius cifra la clave AES con la clave pública RSA del Gran Maestro ---
    std::string encryptedAesKey;
    try {
        // Load the Grand Master's public RSA key from the .der file.
        // No HexDecoder is needed here as .der is a binary format.
        CryptoPP::FileSource fs("claves/gm_publica.der", true);
        CryptoPP::RSAES_OAEP_SHA_Encryptor rsaEncryptor(fs);

        // Encrypt the AES key using the RSA public key
        CryptoPP::StringSource(aesKey.data(), aesKey.size(), true,
            new CryptoPP::PK_EncryptorFilter(rng, rsaEncryptor,
                new CryptoPP::StringSink(encryptedAesKey)
            )
        );
        std::cout << "[Pedrius] PASO 2: Clave AES cifrada con RSA y lista para enviar." << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Pedrius al cifrar la clave de sesión: " << e.what() << std::endl;
        return 1;
    }

    // --- PASO 3: El Gran Maestro descifra la clave AES con su clave privada RSA ---
    CryptoPP::SecByteBlock decryptedAesKey(CryptoPP::AES::DEFAULT_KEYLENGTH); // Initialize with correct size
    try {
        CryptoPP::AutoSeededRandomPool prng; // Random number generator for decryption

        // Create an RSA private key object
        CryptoPP::RSA::PrivateKey privateKey;

        // Load the Grand Master's private RSA key from the .der file.
        // IMPORTANT: Removed HexDecoder as .der is binary.
        CryptoPP::FileSource fs_priv("claves/gm_privada.der", true); // Use a different FileSource object name
        privateKey.Load(fs_priv); // Load the private key

        // Create an RSA decryptor using the private key
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        // Decrypt the encrypted AES key received from Pedrius
        // The decrypted key will be placed into 'decryptedAesKey'
        CryptoPP::StringSource(encryptedAesKey, true,
            new CryptoPP::PK_DecryptorFilter(prng, decryptor,
                new CryptoPP::ArraySink(decryptedAesKey.data(), decryptedAesKey.size())
            )
        );

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Gran Maestro al descifrar la clave de sesión: " << e.what() << std::endl;
        return 1;
    }

    // Encode and display the decrypted AES key for verification
    encodedKey.clear(); // Clear previous encoded key
    CryptoPP::StringSource(decryptedAesKey.data(), decryptedAesKey.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedKey))
    );
    std::cout << "\n[Gran Maestro] PASO 3: Clave de sesión AES descifrada -> " << encodedKey << std::endl;

    // Compare the original and decrypted AES keys
    if (aesKey == decryptedAesKey) {
        std::cout << "[Sistema] ¡ÉXITO! Ambas partes ahora comparten la misma clave de sesión secreta." << std::endl;
    } else {
        std::cout << "[Sistema] ¡FALLO! Las claves no coinciden." << std::endl;
        return 1;
    }

    // --- PASO 4: El canal seguro está establecido. ---
    // Now you can proceed with AES communication using aesKey (Pedrius) and decryptedAesKey (Gran Maestro)
    // For example, to encrypt a message from Pedrius using the AES session key:
    std::string plainText = "¡Hola Gran Maestro! Este es un mensaje secreto.";
    std::string cipherText;
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE); // Initialization Vector
    rng.GenerateBlock(iv, iv.size());

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryptor;
        aesEncryptor.SetKeyWithIV(aesKey, aesKey.size(), iv.data(), iv.size());

        CryptoPP::StringSource(plainText, true,
            new CryptoPP::StreamTransformationFilter(aesEncryptor,
                new CryptoPP::StringSink(cipherText)
            )
        );
        std::cout << "\n[Pedrius] Mensaje original: \"" << plainText << "\"" << std::endl;
        std::string encodedCipher;
        CryptoPP::StringSource(cipherText, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedCipher)));
        std::cout << "[Pedrius] Mensaje cifrado (enviado): " << encodedCipher << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Pedrius al cifrar el mensaje: " << e.what() << std::endl;
        return 1;
    }

    // And for Gran Maestro to decrypt the message:
    std::string recoveredPlainText;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryptor;
        aesDecryptor.SetKeyWithIV(decryptedAesKey, decryptedAesKey.size(), iv.data(), iv.size()); // Use the same IV!

        CryptoPP::StringSource(cipherText, true,
            new CryptoPP::StreamTransformationFilter(aesDecryptor,
                new CryptoPP::StringSink(recoveredPlainText)
            )
        );
        std::cout << "[Gran Maestro] Mensaje descifrado: \"" << recoveredPlainText << "\"" << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Gran Maestro al descifrar el mensaje: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
