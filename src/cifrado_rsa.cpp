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
    CryptoPP::AutoSeededRandomPool generador; // Generador de números aleatorios para RSA
    std::string textoCifrado, textoHex;
    std::string mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";

    std::cout << "Mensaje Original: " << mensaje << std::endl;

    try {
        // Carga la clave pública RSA desde archivo binario DER
        CryptoPP::FileSource archivo("claves/gm_publica.der", true);
        CryptoPP::RSAES_OAEP_SHA_Encryptor cifrador(archivo); // Configura el cifrador RSA con OAEP

        // Cifra el mensaje usando RSA con la clave pública
        CryptoPP::StringSource(mensaje, true,
            new CryptoPP::PK_EncryptorFilter(generador, cifrador,
                new CryptoPP::StringSink(textoCifrado)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error durante el proceso de cifrado: " << e.what() << std::endl;
        return 1;
    }

    // Convierte el resultado cifrado a hexadecimal para mostrar
    CryptoPP::StringSource(textoCifrado, true, 
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(textoHex))
    );
    
    std::cout << "\nMensaje Cifrado :" << std::endl;
    std::cout << textoHex << std::endl;
    return 0;
}