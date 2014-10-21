

#include <stdio.h>
#include <stdlib.h>

#include "ts_base.h"

int main(int argc, char **argv)
{
	//!< encode test
	int src_str_size/* = 60*/; 
	unsigned char *src_str = "hello world!";/* = NULL;*/
	int encode_str_size;
	EVP_ENCODE_CTX ctx;
	unsigned char *decode_str = NULL;
	int decode_str_size = 0;
	int len = 20;   //!< 每次decode 的字节数  
	int decode_len = 0;
	int offset = 0;
	int ret;



	unsigned char *encode_str = NULL;
	src_str_size = strlen(src_str);
	/*src_str = (unsigned char *)malloc(src_str_size);*/
	/*memset(src_str, '1', src_str_size);*/



	encode_str = (unsigned char *)malloc( (src_str_size - 1) / 3 * 4 + 4);
	encode_str_size = EVP_EncodeBlock(encode_str, src_str, src_str_size);

	printf("encode_str_size=%d encode_str:'%s'/n \n", encode_str_size, encode_str);
	//!< decode test

	EVP_DecodeInit(&ctx);

	decode_str = (unsigned char *)malloc(src_str_size);

	while(1)
	{   
		if(offset + len > encode_str_size)
		{   
			len = encode_str_size - offset;
		}   

		ret = EVP_DecodeUpdate(&ctx, decode_str + decode_str_size, &decode_len, 
			encode_str + offset, len);
		if(ret == 0) break;
		if(ret == -1)
		{
			printf("error...\n");
			break;
		}
		offset += len;
		decode_str_size += decode_len;
	}
	EVP_DecodeFinal(&ctx, decode_str, &decode_len);
	decode_str_size += decode_len;
	printf("decode_str:'%s' decode_str_len=%d \n",
		decode_str, decode_str_size);

	getchar();

	return 0;

}














