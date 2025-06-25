#include <iostream>
#include <string>
#include "cryptlib.h"
#include "rsa.h"
#include "osrng.h"
#include "files.h"
#include "hex.h"

int main() {
    CryptoPP::AutoSeededRandomPool rng;
    std::string encrypted, encoded;
    std::string message = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";

    std::cout << "--- Cifrado RSA para el Gran Maestro ---" << std::endl;
    std::cout << "Mensaje Original: " << message << std::endl;

    try {
        // INTENTO FINAL: Cargar la clave desde el formato binario puro (DER)
        CryptoPP::FileSource fs("claves/gm_publica.der", true); // <-- Apuntando al archivo .der
        CryptoPP::RSAES_OAEP_SHA_Encryptor e(fs);

        CryptoPP::StringSource(message, true,
            new CryptoPP::PK_EncryptorFilter(rng, e,
                new CryptoPP::StringSink(encrypted)
            )
        );

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error durante el proceso de cifrado: " << e.what() << std::endl;
        return 1;
    }

    CryptoPP::StringSource(encrypted, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));
    std::cout << "\n¡ÉXITO! Mensaje Cifrado (Hex):" << std::endl;
    std::cout << encoded << std::endl;

    return 0;
}