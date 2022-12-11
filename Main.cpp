#include <iostream>
#include <string>
#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>

//SHA-256 Constants
const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//SHA-256 functions
uint32_t rightRotate(uint32_t n, uint32_t d) {
	return (n >> d) | (n << (32 - d));
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (~x & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t Sigma0(uint32_t x) {
	return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
}

uint32_t Sigma1(uint32_t x) {
	return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
}

uint32_t sigma0(uint32_t x) {
	return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >> 3);
}

uint32_t sigma1(uint32_t x) {
	return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >> 10);
}

//SHA-256 Hash
std::array<uint32_t, 8> sha256(std::string s) {
	//Pre-processing
	const uint32_t messageLength = s.length() * 8;
	const uint32_t numberOfBlocks = ((messageLength + 1) / 512) + 1;
	const uint32_t numberOfWords = numberOfBlocks * 16;
	std::array<uint32_t, 64> M;
	for (uint32_t i = 0; i < numberOfWords; i++) {
		M[i] = 0;
	}

	//Break message into blocks
	for (uint32_t i = 0; i < s.length(); i++) {
		M[i >> 2] |= (uint8_t)s[i] << ((i % 4) * 8);
	}

	//Append a '1' bit
	M[s.length() >> 2] |= 0x80 << (((s.length() % 4)) * 8);

	//Append message length
	M[numberOfWords - 2] = messageLength;

	//Initialize hash values
	std::array<uint32_t, 8> H = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	//Main loop
	for (uint32_t i = 0; i < numberOfBlocks; i++) {
		//Create a 64-entry message schedule array
		std::array<uint32_t, 64> W;
		for (uint32_t t = 0; t < 16; t++) {
			W[t] = M[t + (i * 16)];
		}
		for (uint32_t t = 16; t < 64; t++) {
			W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
		}

		//Initialize working variables
		uint32_t a = H[0];
		uint32_t b = H[1];
		uint32_t c = H[2];
		uint32_t d = H[3];
		uint32_t e = H[4];
		uint32_t f = H[5];
		uint32_t g = H[6];
		uint32_t h = H[7];

		//Main compression loop
		for (uint32_t t = 0; t < 64; t++) {
			uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + k[t] + W[t];
			uint32_t T2 = Sigma0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		//Compute intermediate hash value
		H[0] = a + H[0];
		H[1] = b + H[1];
		H[2] = c + H[2];
		H[3] = d + H[3];
		H[4] = e + H[4];
		H[5] = f + H[5];
		H[6] = g + H[6];
		H[7] = h + H[7];
	}

	//Return final hash
	return H;
}

int main() {
	//Read in entire book of Mark
	std::ifstream file("/path/to/book/of/mark");
	std::stringstream buffer;
	buffer << file.rdbuf();
	std::string bookOfMark = buffer.str();

	//Compute and print SHA-256 hash for the book of Mark
	std::array<uint32_t, 8> hash = sha256(bookOfMark);
	for (uint32_t i = 0; i < 8; i++) {
		std::cout << std::hex << hash[i];
	}
  
}
