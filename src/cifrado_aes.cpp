#include <iostream>
#include <string>

// Cabeceras de Crypto++
#include "cryptlib.h"
#include "hex.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "osrng.h"

// no se usará arcv por simpleza. Editar acá el mensaje sea de cambiar.
std::string plainText = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";

// no se usarán namespaces por los conflictos

int main() {
    // 1. Definir la Clave Secreta
    std::string hexKey = "6F708192A3B4C5D6E7F8A22023730521"; // 32 hex = 256 bits

    // Almacenar  clave segura
    CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(hexKey.data()), hexKey.size());

    // 2. Declarar mensajes para encriptación
    std::string cipherText, encodedText;

    std::cout << "Mensaje Original: " << plainText << std::endl;
    std::cout << "Clave usada (Hex): " << hexKey << std::endl;

    // 3. Cifrar el Mensaje
    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
        e.SetKey(key, key.size());

        CryptoPP::StringSource(plainText, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipherText)
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cerr << "Error en el cifrado: " << e.what() << std::endl;
        return 1;
    }

    // 4. Codificar a Hexadecimal para mostrar
    CryptoPP::StringSource(cipherText, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encodedText)
        )
    );

    std::cout << "Mensaje Cifrado (Hex): " << encodedText << std::endl;

    return 0;
}
