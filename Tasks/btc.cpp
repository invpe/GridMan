#include <iostream>
#include <stdio.h>
#include <assert.h>
#include <random>    
#include <random>
#include <iostream>
#include <string>
#include <cstring>
#include <algorithm>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sodium.h>
#include "CJZon.h"
#include "CSerializer.h"
#include "CGridTask.h"
#include "CBigInteger.h"

#define SHA256M_BLOCK_SIZE 32 
static const uint32_t EXPONENT_SHIFT = 24;
static const uint32_t MANTISSA_MASK = 0xffffff;

std::string strBTCAddress = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; 
 
#pragma pack(push, 1) // Set alignment to 1 byte
struct Block
{
    uint32_t version;           // Block version
    uint8_t previous_block[32]={}; // Previous block hash
    uint8_t merkle_root[32]={};    // Merkle root hash
    uint32_t ntime;             // Timestamp
    uint32_t nbits;             // Target difficulty
    uint32_t nonce;             // Nonce
 
};
#pragma pack(pop) // Reset alignment to default

uint32_t toLittleEndian(uint32_t value) {
    return ((value & 0xFF) << 24) |
           ((value & 0xFF00) << 8) |
           ((value & 0xFF0000) >> 8) |
           ((value & 0xFF000000) >> 24);
}

 static void reverseBytes(uint8_t *data, size_t len)
{
    size_t half_len = len / 2;
    for (size_t i = 0; i < half_len; ++i)
    {
        uint8_t temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}
uint8_t hex(char ch)
{
    uint8_t r = (ch > 57) ? (ch - 55) : (ch - 48);
    return r & 0x0F;
} 
void hexStringToByteArray(const char *hexString, uint8_t *output)
{ 
    while (*hexString)
    {
        *output = (hex(*hexString++) << 4) | hex(*hexString++);
        output++;
    }
}

std::string byteArrayToHexString(const uint8_t *byteArray, size_t length)
{
    static const char hex_array[] = "0123456789abcdef";
    std::string result;

    for (size_t i = 0; i < length; i++)
    {
        uint8_t value = byteArray[i];
        result += hex_array[value >> 4];
        result += hex_array[value & 0xF];
    }

    return result;
}
 
/**
 * Reverses the order of bytes in the given data array and flips each byte.
 *
 * @param data The data array to be reversed and flipped.
 * @param len The length of the data array.
 */
static void reverseBytesAndFlip(uint8_t *data, size_t len)
{
    for (unsigned int i = 0; i < len / 4; ++i)
    {
        uint8_t temp[4];
        for (int j = 0; j < 4; ++j)
        {
            temp[j] = data[i * 4 + j];
        }
        for (int j = 0; j < 4; ++j)
        {
            data[i * 4 + j] = temp[3 - j];
        }
    }
}
static int bigEndianCompare(const unsigned char *a, const unsigned char *b, size_t byte_len)
{
    for (size_t i = 0; i < byte_len; ++i)
    {
        if (a[i] < b[i])
            return -1;
        else if (a[i] > b[i])
            return 1;
    }
    return 0;
}
/**
 * Compares two byte arrays in little-endian order.
 *
 * @param a The first byte array to compare.
 * @param b The second byte array to compare.
 * @param byte_len The length of the byte arrays.
 * @return -1 if a is less than b, 1 if a is greater than b, 0 if they are equal.
 */static int littleEndianCompare(const unsigned char *a, const unsigned char *b, size_t byte_len)
{
    for (size_t i = byte_len - 1; ; --i)
    {
        if (a[i] < b[i])
            return -1;
        else if (a[i] > b[i])
            return 1;
         if (i == 0) 
            break;      
    }
    return 0;
} 
void sha256_double(const void *data, size_t len, uint8_t output[32]) {
    uint8_t intermediate_hash[32];

    // First SHA-256 hash
    crypto_hash_sha256(intermediate_hash, (const unsigned char *)data, len);

    // Second SHA-256 hash
    crypto_hash_sha256(output, intermediate_hash, sizeof(intermediate_hash));
}
 
std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + 1;
        end = str.find(delimiter, start);
    }

    tokens.push_back(str.substr(start, end - start));
    return tokens;
}
 
void generateCoinbaseHash(const std::string &coinbase, std::string &coinbase_hash)
{    
    const size_t len = coinbase.length();
    uint8_t coinbaseBytes[len / 2];
    hexStringToByteArray(coinbase.c_str(), coinbaseBytes);
    uint8_t hash[SHA256M_BLOCK_SIZE];
    sha256_double(coinbaseBytes, len / 2, hash);
    coinbase_hash = byteArrayToHexString(hash, SHA256M_BLOCK_SIZE); 
}
void calculateMerkleRoot(const std::string &coinbase_hash, const std::vector<std::string> &merkle_branch, std::string &merkle_root)
{
    uint8_t hash[SHA256M_BLOCK_SIZE] = {};
    hexStringToByteArray(coinbase_hash.c_str(), hash);      
    for (const auto &branch : merkle_branch)
    {

        uint8_t merkle_branch_bin[32];
        hexStringToByteArray(branch.c_str(), merkle_branch_bin);

        uint8_t merkle_concatenated[SHA256M_BLOCK_SIZE * 2];
        for (size_t j = 0; j < 32; j++)
        {
            merkle_concatenated[j] = hash[j];
            merkle_concatenated[32 + j] = merkle_branch_bin[j];
        }
 
        sha256_double(merkle_concatenated, sizeof(merkle_concatenated), hash);
    }

    merkle_root = byteArrayToHexString(hash, SHA256M_BLOCK_SIZE);
}


// Adjust the function to accept a reference to a std::mt19937 generator
std::string generate_extra_nonce2(int extranonce2_size, std::mt19937& gen) {
    // Use a uniform distribution to generate random numbers between 0 and UINT32_MAX
    std::uniform_int_distribution<uint32_t> dist(0, std::numeric_limits<uint32_t>::max());

    // Create a stringstream for hexadecimal conversion
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    // Calculate the number of hex digits needed (2 digits per byte)
    int num_hex_digits = 2 * extranonce2_size;

    // Depending on the size requested, generate the appropriate number of random values
    for (int i = 0; i < extranonce2_size / 4; ++i) {
        uint32_t randomValue = dist(gen);
        // Convert the random number to a hex string with padding if necessary
        ss << std::setw(8) << randomValue;  // Each uint32_t gives 8 hex digits
    }

    // Ensure the string is not longer than required (in case of overflow)
    std::string result = ss.str();
    if (result.length() > num_hex_digits) {
        result = result.substr(result.length() - num_hex_digits);
    }

    // Return the formatted string
    return result;
}


std::string generate_extra_nonce1(int idx)
{
// Generate a random number between 0 and INT_MAX

    uint32_t randomValue = idx;

    // Calculate the required length of the hex string
    int hexStringLength = 2 * 4 + 1; // 2 characters per byte + 1 for null terminator

    // Allocate memory for the extranonce2 string
    char *extranonce2 = new char[hexStringLength];

    // Convert the random number to a hex string
    snprintf(extranonce2, hexStringLength, "%u", randomValue);
    while (static_cast<int>(strlen(extranonce2)) < hexStringLength - 1)
    {
        char temp[hexStringLength];
        snprintf(temp, hexStringLength, "0%s", extranonce2);
        strcpy(extranonce2, temp);
    }
    return std::string(extranonce2);
} 
void nbitsToTarget(const std::string& nbits, uint8_t target[32]) {
    memset(target, 0, 32);  // Initialize the target array to zeros

     // Convert the nbits string to a 32-bit integer.
        char *endPtr;
        uint32_t bits_value = strtoul(nbits.c_str(), &endPtr, 16);

        // Check for conversion errors
        if (*endPtr != '\0' || bits_value == 0)
        {
            // Handle the error (print a message, set a default value, etc.).
            printf("Error: Invalid nbits value\n");
            exit(0);
        }

        // Extract the exponent and mantissa from bits_value.
        uint32_t exp = bits_value >> EXPONENT_SHIFT;
        uint32_t mant = bits_value & MANTISSA_MASK;

        // Calculate the shift value.
        uint32_t shift = 8 * (exp - 3);

        // Calculate the byte and bit positions.
        uint32_t sb = shift / 8;
        uint32_t rb = shift % 8;

        // Calculate the target value based on the exponent and mantissa.
        target[sb] = (mant << rb);
        target[sb + 1] = (mant >> (8 - rb));
        target[sb + 2] = (mant >> (16 - rb));
        target[sb + 3] = (mant >> (24 - rb));
}
static void hexInverse(unsigned char *hex, size_t len, char *output)
{
    for (size_t i = len - 1; i < len; --i)
    {
        sprintf(output, "%02x", hex[i]);
        output += 2;
    }
}

/**
 * Converts a string to little-endian byte representation.
 *
 * @param in The input string to convert.
 * @param output The output buffer to store the converted bytes.
 */
void stringToLittleEndianBytes(const char *in, uint8_t *output)
{
    size_t len = strlen(in);
    assert(len % 2 == 0);

    for (size_t s = 0, b = (len / 2 - 1); s < len; s += 2, --b)
    {
        output[b] = (unsigned char)(hex(in[s]) << 4) + hex(in[s + 1]);
    }
}
void print_hex(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
} 
std::string convert_to_little_endian(const std::string& input) {
    std::string reversed_input;
    for (size_t i = input.size(); i > 0; i -= 2) {
        reversed_input += input.substr(i - 2, 2);
    } 
    return reversed_input;
} 

bool compareHashToTarget(const uint8_t* blockHash, const uint8_t* target) {
    // Compare each byte of the block hash and the target
    for (int i = 0; i < 32; ++i) {
        if (blockHash[i] < target[i]) {
            // If any byte of the block hash is less than the corresponding byte of the target, return true
            return true;
        } else if (blockHash[i] > target[i]) {
            // If any byte of the block hash is greater than the corresponding byte of the target, return false
            return false;
        }
        // If they are equal, continue to the next byte
    }
    // If all bytes are equal, return true (block hash is less than or equal to the target)
    return true;
}

// Function to convert a value to little-endian hexadecimal representation
std::string littleEndian(uint32_t value) {
    std::ostringstream oss;
    // Use std::hex to format as hexadecimal
    oss << std::hex << std::setw(8) << std::setfill('0') << value;
    // Convert to little-endian by reversing byte order
    std::string hexStr = oss.str();
    std::string result;
    for (int i = hexStr.size() - 2; i >= 0; i -= 2) {
        result += hexStr.substr(i, 2);
    }
    return result;
}
// Function to convert an integer to little-endian byte representation
std::string integerToLittleEndian(uint32_t value) {
    std::string result;
    for (int i = 0; i < sizeof(value); ++i) {
        result += static_cast<char>((value >> (i * 8)) & 0xFF);
    }
    return result;
}
// Function to compare two hashes
bool isHashLessThanTarget(const uint8_t* hash, const uint8_t* target, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (hash[i] < target[i]) {
            return true;  // Hash is less than target
        } else if (hash[i] > target[i]) {
            return false; // Hash is greater than target
        }
        // If hash[i] == target[i], continue checking next byte
    }
    return false; // Hash is equal to target
} 

void serializeBlockHeader(const Block& block, std::vector<uint8_t>& buffer) {
    buffer.clear();

    // Version: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.version), reinterpret_cast<const uint8_t*>(&block.version) + sizeof(block.version));

    // Previous Block Hash: little endian, assuming it's provided correctly
    buffer.insert(buffer.end(), block.previous_block, block.previous_block + 32);

    // Merkle Root: 
    // The output of the SHA-256 hash function, such as the hash of the Merkle root, is typically represented in big endian format by convention. 
    std::vector<uint8_t> merkleRoot(block.merkle_root, block.merkle_root + 32);
    std::reverse(merkleRoot.begin(), merkleRoot.end());
    buffer.insert(buffer.end(), merkleRoot.begin(), merkleRoot.end());

    // Time: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.ntime), reinterpret_cast<const uint8_t*>(&block.ntime) + sizeof(block.ntime));

    // Bits: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.nbits), reinterpret_cast<const uint8_t*>(&block.nbits) + sizeof(block.nbits));

    // Nonce: little endian
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&block.nonce), reinterpret_cast<const uint8_t*>(&block.nonce) + sizeof(block.nonce));
}
 
std::string strPayload;
CSerializer _Serializer;
CBigInteger EndIndex;

uint32_t uiTick = time(0);
uint32_t uiCombinationsPerSecond = 0;

// Keep found in this string
std::string strOutputPayload ="";  

int main(int argc, char **argv)
{ 
    // Sanity check
    if(argc < 2)
    {
        printf("Error, no payload passed as an argument\n");
        return -1;
    }

     if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed" << std::endl;
        return -1;
    } 

    
    Jzon::Node rootNode;
    Jzon::Parser _Parser; 

    // Subscribe
    std::string id;
    std::string extranonce1;
    int extranonce2_size;

    // Notification
    std::string job_id;
    std::string prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<std::string> merkle_branch;
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean_jobs;

    std::string extranonce2;


    // Dump some handy output
    strPayload = argv[1];
    printf("Started with payload: %s\n", strPayload.data());
      
	// Incoming / Outgoing Payloads
    // We will store our Incoming payload and Outgoung payload in two
    // vectors of uint8_t 1bytes
	std::vector<uint8_t> m_vIncomingPayload;
	std::vector<uint8_t> m_vOutgoingPayload;


    // 1. Initialize the Task by reading in the Payload data from
    // provided filename
	if (CGridTask::Init(m_vIncomingPayload, strPayload) == false)
	{
        // This means, that Worker can have some problems
        // See Worker log
		printf("Info: Error, couldn't initialize the Payload\n");

		//
		return -1;
	}  

    

    // Set Serializer data
	_Serializer.Set(m_vIncomingPayload);
    
    // Obtain btc address
    std::string strBTCAddress = _Serializer.Read_string();

    // Obtain first JSON
    std::string strFirstJSON = _Serializer.Read_string();

    // Obtain second json
    std::string strSecondJSNO = _Serializer.Read_string();
 
    // Obtain combinations count
    uint32_t uiIterations = _Serializer.Read_uint32();
    
    
    printf("[INFO] Going %u combinations, fingers crossed.\n",uiIterations);
 
    //
    // Clear the payload file as we will be using intermittent payloads
    //
    _Serializer.Reset(); 
    _Serializer.Write_string(strOutputPayload);
    CGridTask::Deinit(_Serializer.GetBuffer(), strPayload);
 
    
    // Parse first JSON
    rootNode = _Parser.parseString(strFirstJSON);
    if (!rootNode.isValid()) {
        std::cerr << "[ERROR] Error parsing JSON\n";
        return -1;
    }

    Jzon::Node jzResults = rootNode.get("result");
    Jzon::Node A = jzResults.get(0);
    Jzon::Node B = A.get(0);
    Jzon::Node C = B.get(1);
    id = C.toString();
    extranonce1 = jzResults.get(1).toString();   
    extranonce2_size = jzResults.get(2).toInt();  

    // Parse second JSON
    rootNode = _Parser.parseString(strSecondJSNO);
    if (!rootNode.isValid()) {
        std::cerr << "[ERROR] Error parsing JSON 3\n";
        return -1;
    }
    jzResults   = rootNode.get("params");
    job_id  = jzResults.get(0).toString();
    prevhash = jzResults.get(1).toString();  
    coinb1  = jzResults.get(2).toString();   
    coinb2  = jzResults.get(3).toString();  
    version = jzResults.get(5).toString(); 
    nbits   = jzResults.get(6).toString();     
    ntime   = jzResults.get(7).toString(); 
    clean_jobs  = jzResults.get(8).toInt();  
     
    ///////////////////////////
    // Done with parsing     //
    /////////////////////////// 

    // Prepare a random machine
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::uint32_t> dist(0, std::numeric_limits<std::uint32_t>::max());

    // Calculate target this never changes    
    uint8_t target[32];
    nbitsToTarget(nbits,target);
    // Reverse it
    reverseBytes(target,32);

    for(uint32_t i = 0; i < uiIterations;i++)
    {
        Block block;
        extranonce2 = generate_extra_nonce2(extranonce2_size,gen);   

        // Prev hash ready to use from ckpool (already reversed)
        hexStringToByteArray(prevhash.c_str(), block.previous_block);                            

        // Calculate coinbase
        const std::string coinbase = coinb1 + extranonce1 + extranonce2 + coinb2;    
        std::string coinbase_hash;
        generateCoinbaseHash(coinbase, coinbase_hash);
        
        // Calculate merkle
        //The output of the SHA-256 hash function, such as the hash of the Merkle root, is typically represented in big endian format by convention. 
        std::string merkle_root;
        calculateMerkleRoot(coinbase_hash, merkle_branch, merkle_root);
        hexStringToByteArray(merkle_root.c_str(), block.merkle_root);
        
        // Update block header
        // https://bitcoin.stackexchange.com/questions/59614/mining-block-header-bit-reversing/59615#59615
        block.version   = strtoul(version.c_str(), nullptr, 16);
        block.ntime     = strtoul(ntime.c_str(), nullptr, 16);   
        block.nbits     = strtoul(nbits.c_str(), nullptr, 16);   
        block.nonce     = dist(gen); // Already in little endian (LE machine)

        // Altering ntime is an option
        // Example: Maximum allowed future time difference (Bitcoin network's rule)
        std::uniform_int_distribution<std::uint32_t> distTime(0, 7200);        
        block.ntime += distTime(gen);     
   

        // Finaly build the block header
        std::vector<uint8_t> vHeader;
        serializeBlockHeader(block,vHeader);

        // Hash it
        uint8_t block_hash[32];    
        sha256_double(vHeader.data(), vHeader.size(), block_hash); 

        // Reverse as output of SHA256 is always BIG endian, but our target is LE
        // The output of the SHA-256 hash function, such as the hash of the Merkle root, is typically represented in big endian format by convention. 
        reverseBytes(block_hash,32);

        // Block and Target are BE, compare
        bool bSuccess= false;
        if(littleEndianCompare(block_hash,target,32)<0)
        {
            printf("[SUCCESS] BLOCK FOUND %u %s\n",block.nonce,extranonce2.data());            
            bSuccess=true;
            
        }    
        std::ostringstream oss;    
        oss << "{\"status\":" << (bSuccess ? "true" : "false") // Assuming bSuccess is a boolean
            << ",\"job_id\":\"" << job_id << "\","
            << "\"extranonce2\":\"" << extranonce2 << "\","
            << "\"ntime\":\"" << std::setfill('0') << std::setw(8) << std::hex << block.ntime << "\","
            << "\"nonce\":\"" << std::setfill('0') << std::setw(8) << std::hex << block.nonce << "\"}\n"; 
        strOutputPayload = oss.str();

        if(bSuccess==true)
            break;
   
        uiCombinationsPerSecond++;

        if(time(0) - uiTick > 1)
        {
            printf("[INFO] We're doing %u combinations per second\n", uiCombinationsPerSecond);
            uiCombinationsPerSecond = 0;
            uiTick = time(0);
        }
    } 
	_Serializer.Reset();

    // Avoid Write_String it will add a size header in front, we need plain text
    for(size_t s = 0; s < strOutputPayload.size(); s++) 
        _Serializer.Write_uint8(strOutputPayload[s]);     
    
	CGridTask::Deinit(_Serializer.GetBuffer(), strPayload);
 
	
	//
	return 0;
}
