#include <iostream>
#include <stdint.h>
#include <memory.h>
#include <gtest/gtest.h>


uint32_t iter_key[32]; 
typedef uint8_t substitution_t[128];
uint32_t key[8];


void magma_key_expansion(uint32_t key[])
{

  for ( int i = 0 ; i < 8 ; i ++ )
  {
  	iter_key[i] = key[7-i];
  	//std::cout << "K" << std::dec <<i << ": " << std::hex << iter_key[i] << std::endl ;
  }
  
  for ( int i = 8 ; i < 16 ; i ++ )
  {
  	iter_key[i] = key[15-i];
  	//std::cout << "K" << std::dec << i << ": " << std::hex << iter_key[i] << std::endl ;
  }
  
  for ( int i = 16 ; i < 24 ; i ++ )
  {
  	iter_key[i] = key[23-i];
  	//std::cout << "K" << std::dec << i << ": " << std::hex << iter_key[i] << std::endl ;
  }   
  
  for ( int i = 24 ; i < 32 ; i ++ )
  {
  	iter_key[i] = key[i-24];
  	//std::cout << "K" << std::dec << i << ": " << std::hex << iter_key[i] << std::endl ;
  }
}





substitution_t pi = {
    0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
    0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
    0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
    0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
    0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
    0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
    0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
    0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
};

void magma_round(uint32_t round_key, uint32_t & a1, uint32_t & a0)
{
    
    uint32_t g = a0 + round_key;
    uint32_t t =
          ((pi[0   + ((g & 0x0000000f) >>  0)]) <<  0)
        | ((pi[16  + ((g & 0x000000f0) >>  4)]) <<  4)
        | ((pi[32  + ((g & 0x00000f00) >>  8)]) <<  8)
        | ((pi[48  + ((g & 0x0000f000) >> 12)]) << 12)
        | ((pi[64  + ((g & 0x000f0000) >> 16)]) << 16)
        | ((pi[80  + ((g & 0x00f00000) >> 20)]) << 20)
        | ((pi[96  + ((g & 0x0f000000) >> 24)]) << 24)
        | ((pi[112 + ((g & 0xf0000000) >> 28)]) << 28);
    a1 ^= ((t << 11) | (t >> 21));
}

/* Зашифрование одного блока данных */
uint64_t magma_encrypt_block(uint32_t* key, uint64_t block)
{
    	uint32_t a0 = block % 0x100000000;
	uint32_t a1 = block >> 32 ;
	uint32_t round_key;
	//std::cout << std::hex << a1 << "||" << a0 << std::endl; 
	
	for (int round  =  0 ;  round < 31 ; round ++ )
	{
		round_key = iter_key[round];
		magma_round(round_key, a1, a0);
		
		uint32_t temp;
		temp = a0;
		a0 = a1;
		a1 = temp;
		////std::cout << std::hex << a1 << "||" << a0 << std::endl; 
	}

	round_key = iter_key[31];
	magma_round(round_key, a1, a0);
	//std::cout << std::hex << a1 << "||" << a0 << std::endl; 
	uint64_t out_block = ( a1 * 0x100000000) + a0;
	return out_block;  
}

uint64_t magma_decrypt_block(uint32_t* key, uint64_t block)
{
    	uint32_t a0 = block % 0x100000000;
	uint32_t a1 = block >> 32 ;
	uint32_t round_key;
	//std::cout << std::hex << a1 << "||" << a0 << std::endl; 
	
	
	for (int round  =  31 ;  round > 0  ; round -- )
	{
		round_key = iter_key[round];
		magma_round(round_key, a1, a0);
		
		uint32_t temp;
		temp = a0;
		a0 = a1;
		a1 = temp;
		//std::cout << "K" << std::dec << round+1 << "  "<< std::hex << round_key << ":   " << std::hex << a1 << "||" << a0 << std::endl; 
	}
	
	round_key = iter_key[0];
	magma_round(round_key, a1, a0);
	
	uint64_t out_block = ( a1 * 0x100000000 ) + a0;
	return out_block;
}


TEST(EncryptionTest, GOST_EncOut)
{
	ASSERT_EQ(0x4ee901e5c2d8ca3d, magma_encrypt_block(key, 0xfedcba9876543210));	
}

TEST(DecryptionTest, GOST_DecOut)
{
	ASSERT_EQ(0xfedcba9876543210, magma_decrypt_block(key, 0x4ee901e5c2d8ca3d));	
}

int main(int argc, char *argv[])
{
	//TEST_INPUT_DATA
	//uint32_t key[8];
	key[0] = 0xfcfdfeff;
	key[1] = 0xf8f9fafb;
	key[2] = 0xf4f5f6f7;
	key[3] = 0xf0f1f2f3;
	key[4] = 0x33221100;
	key[5] = 0x77665544;
	key[6] = 0xbbaa9988;
	key[7] = 0xffeeddcc;
	
	magma_key_expansion(key);
	
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
	
}
