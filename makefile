all:
	g++ -o src/canal_seguro src/canal_seguro.cpp -L./src -l:libcryptopp.a -I./cryptopp-master/
	g++ -o src/cifrado_aes src/cifrado_aes.cpp -L./src -l:libcryptopp.a -I./cryptopp-master/
	g++ -o src/cifrado_rsa src/cifrado_rsa.cpp -L./src -l:libcryptopp.a -I./cryptopp-master/
