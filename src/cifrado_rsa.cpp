/*
 * Programa de cifrado RSA con clave pública
 * Cifra un mensaje usando la clave pública RSA del Gran Maestro y muestra el resultado en hexadecimal
 */

#include <iostream>
#include <string>
#include "cryptlib.h"
#include "rsa.h"
#include "osrng.h"
#include "files.h"
#include "hex.h"

int main() {
    CryptoPP::AutoSeededRandomPool generador;
    std::string textoCifrado, textoHex;
    std::string mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";

    std::cout << "--- Cifrado RSA para el Gran Maestro ---" << std::endl;
    std::cout << "Mensaje Original: " << mensaje << std::endl;

    try {
        CryptoPP::FileSource archivo("claves/gm_publica.der", true);
        CryptoPP::RSAES_OAEP_SHA_Encryptor cifrador(archivo);

        CryptoPP::StringSource(mensaje, true,
            new CryptoPP::PK_EncryptorFilter(generador, cifrador,
                new CryptoPP::StringSink(textoCifrado)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error durante el proceso de cifrado: " << e.what() << std::endl;
        return 1;
    }

    CryptoPP::StringSource(textoCifrado, true, 
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(textoHex))
    );
    
    std::cout << "\n¡ÉXITO! Mensaje Cifrado (Hex):" << std::endl;
    std::cout << textoHex << std::endl;
    return 0;
}