#include <iostream>
#include <string>

// Cabeceras de Crypto++
#include "cryptlib.h"
#include "hex.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "osrng.h"

// NO usaremos 'using namespace CryptoPP;' para evitar ambigüedades

int main() {
    // ROL a utilizar (ejemplo de la carátula)
    std::cout << "Usando ROL: 202373052-1" << std::endl; // [cite: 1]

    // 1. Definir la Clave Secreta
    // Construimos la clave a partir de los datos del informe.
    std::string hexKey = "6F708192A3B4C5D6E7F8A22023730521"; // Clave de 32 bytes (256-bit)

    // Usamos el tipo SecByteBlock de Crypto++ para almacenar la clave de forma segura.
    // Hay que ser explícitos: CryptoPP::SecByteBlock
    CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(hexKey.data()), hexKey.size());

    // 2. Definir el Mensaje Secreto
    std::string plainText = "La cámara descansa bajo el sauce llorón en el jardín del martillo."; // [cite: 17]
    std::string cipherText, encodedText;

    std::cout << "\n--- Cifrado AES ---\n";
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