/*
 * Programa de cifrado AES en modo ECB
 * Cifra un mensaje usando una clave AES predefinida y muestra el resultado en hexadecimal
 */

#include <iostream>
#include <string>
#include "cryptlib.h"
#include "hex.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"

int main() {
    std::string mensajeOriginal = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";
    std::string claveHex = "6F708192A3B4C5D6E7F8A22023730521";
    
    CryptoPP::SecByteBlock clave(reinterpret_cast<const CryptoPP::byte*>(claveHex.data()), claveHex.size());
    std::string textoCifrado, textoHex;

    std::cout << "Mensaje Original: " << mensajeOriginal << std::endl;
    std::cout << "Clave usada (Hex): " << claveHex << std::endl;

    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption cifrador;
        cifrador.SetKey(clave, clave.size());

        CryptoPP::StringSource(mensajeOriginal, true,
            new CryptoPP::StreamTransformationFilter(cifrador,
                new CryptoPP::StringSink(textoCifrado)
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cerr << "Error en el cifrado: " << e.what() << std::endl;
        return 1;
    }

    CryptoPP::StringSource(textoCifrado, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(textoHex))
    );

    std::cout << "Mensaje Cifrado (Hex): " << textoHex << std::endl;
    return 0;
}
