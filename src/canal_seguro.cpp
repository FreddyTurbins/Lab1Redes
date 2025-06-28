/*
 * Simulación de canal de comunicación seguro con cifrado híbrido
 * Implementa intercambio de claves RSA y comunicación cifrada AES entre Pedrius y el Gran Maestro
 */

#include <iostream>
#include <string>
#include <cstring>
#include "cryptlib.h"
#include "rsa.h"
#include "aes.h"
#include "modes.h"
#include "filters.h"
#include "osrng.h"
#include "files.h"
#include "hex.h"
#include "secblock.h"

int main() {
    std::cout << "--- Simulación de Creación de Canal Seguro (Cifrado Híbrido) ---" << std::endl;
    CryptoPP::AutoSeededRandomPool generador;

    CryptoPP::SecByteBlock claveSesion(CryptoPP::AES::DEFAULT_KEYLENGTH);
    generador.GenerateBlock(claveSesion, claveSesion.size());

    std::string claveHex;
    CryptoPP::StringSource(claveSesion.data(), claveSesion.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(claveHex))
    );
    std::cout << "\n[Pedrius] PASO 1: Clave de sesión AES generada -> " << claveHex << std::endl;

    std::string claveCifrada;
    try {
        CryptoPP::RSA::PublicKey clavePublica;
        CryptoPP::FileSource archivo("claves/gm_publica_new.der", true);
        clavePublica.Load(archivo);
        
        CryptoPP::RSAES_OAEP_SHA_Encryptor cifradorRSA(clavePublica);

        CryptoPP::StringSource(claveSesion.data(), claveSesion.size(), true,
            new CryptoPP::PK_EncryptorFilter(generador, cifradorRSA,
                new CryptoPP::StringSink(claveCifrada)
            )
        );
        std::cout << "[Pedrius] PASO 2: Clave AES cifrada con RSA y lista para enviar." << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Pedrius al cifrar la clave de sesión: " << e.what() << std::endl;
        return 1;
    }

    CryptoPP::SecByteBlock claveDescifrada(CryptoPP::AES::DEFAULT_KEYLENGTH);
    try {
        CryptoPP::RSA::PrivateKey clavePrivada;
        CryptoPP::FileSource archivoPrivado("claves/gm_privada_new.der", true);
        clavePrivada.Load(archivoPrivado);

        CryptoPP::RSAES_OAEP_SHA_Decryptor descifradorRSA(clavePrivada);

        std::string claveTemporal;
        CryptoPP::StringSource(claveCifrada, true,
            new CryptoPP::PK_DecryptorFilter(generador, descifradorRSA,
                new CryptoPP::StringSink(claveTemporal)
            )
        );

        if (claveTemporal.size() == CryptoPP::AES::DEFAULT_KEYLENGTH) {
            std::memcpy(claveDescifrada.data(), claveTemporal.data(), claveTemporal.size());
        } else {
            std::cerr << "Error: Tamaño de clave descifrada incorrecto" << std::endl;
            return 1;
        }
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Gran Maestro al descifrar la clave de sesión: " << e.what() << std::endl;
        return 1;
    }

    claveHex.clear();
    CryptoPP::StringSource(claveDescifrada.data(), claveDescifrada.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(claveHex))
    );
    std::cout << "\n[Gran Maestro] PASO 3: Clave de sesión AES descifrada -> " << claveHex << std::endl;

    if (claveSesion == claveDescifrada) {
        std::cout << "[Sistema] ¡ÉXITO! Ambas partes ahora comparten la misma clave de sesión secreta." << std::endl;
    } else {
        std::cout << "[Sistema] ¡FALLO! Las claves no coinciden." << std::endl;
        return 1;
    }

    std::string mensajeOriginal = "¡Hola Gran Maestro! Este es un mensaje secreto.";
    std::string mensajeCifrado;

    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption cifradorAES;
        cifradorAES.SetKey(claveSesion, claveSesion.size());

        CryptoPP::StringSource(mensajeOriginal, true,
            new CryptoPP::StreamTransformationFilter(cifradorAES,
                new CryptoPP::StringSink(mensajeCifrado)
            )
        );
        std::cout << "\n[Pedrius] Mensaje original: \"" << mensajeOriginal << "\"" << std::endl;
        
        std::string mensajeHex;
        CryptoPP::StringSource(mensajeCifrado, true, 
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(mensajeHex))
        );
        std::cout << "[Pedrius] Mensaje cifrado (enviado): " << mensajeHex << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Pedrius al cifrar el mensaje: " << e.what() << std::endl;
        return 1;
    }

    std::string mensajeRecuperado;
    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption descifradorAES;
        descifradorAES.SetKey(claveDescifrada, claveDescifrada.size());

        CryptoPP::StringSource(mensajeCifrado, true,
            new CryptoPP::StreamTransformationFilter(descifradorAES,
                new CryptoPP::StringSink(mensajeRecuperado)
            )
        );
        std::cout << "[Gran Maestro] Mensaje descifrado: \"" << mensajeRecuperado << "\"" << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error en Gran Maestro al descifrar el mensaje: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
