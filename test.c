

#include <stdio.h>
#include <stdlib.h>

#include "ts_base.h"


int test_one()
{
		//!< encode test
	int src_str_size/* = 60*/; 
	unsigned char *src_str = "h������Ϊν����������������������������������������ello qwertyuioplkjhgfdsazxcvbnm,.;'ZXCVBNM<>LKHFADAFQWQTWRY";/* = NULL;*/
	int encode_str_size = 0;
	EVP_ENCODE_CTX ctx;
	unsigned char *decode_str = NULL;
	int decode_str_size = 0;
	int len = 20;   //!< ÿ��decode ���ֽ���  
	int decode_len = 0;
	int offset = 0;
	int ret;



	unsigned char *encode_str = NULL;
	src_str_size = strlen(src_str);
	/*src_str = (unsigned char *)malloc(src_str_size);*/
	/*memset(src_str, '1', src_str_size);*/



	encode_str = (unsigned char *)malloc( (src_str_size - 1) / 3 * 4 + 4);
	//encode_str_size = EVP_EncodeBlock(encode_str, src_str, src_str_size);

	/** 
 * iOriLen:����ǰ�����ݳ���
 * strOrdData:����ǰ����
 * iDstLen:���������ݳ���
 * strDstData:��ű��������ݻ�����
 * B64Encode(32, out, outLen, (unsigned char*)szDstData);
 */
	B64Encode(src_str_size, src_str, &encode_str_size, encode_str, 1);


	printf("encode_str_size=%d encode_str:'%s'  src_str_size = %d \n", encode_str_size, encode_str, src_str_size);
	//!< decode test



	decode_str = (unsigned char *)malloc(src_str_size);
	B64Decode(encode_str_size, encode_str, &decode_str_size, decode_str, 1);

	//int B64Decode(int iOriLen, unsigned char *strOrdData, int *iDstLen, unsigned char* strDstData)

// 	EVP_DecodeInit(&ctx);
// 	while(1)
// 	{   
// 		if(offset + len > encode_str_size)
// 		{   
// 			len = encode_str_size - offset;
// 		}   
// 
// 		ret = EVP_DecodeUpdate(&ctx, decode_str + decode_str_size, &decode_len, 
// 			encode_str + offset, len);
// 		if(ret == 0) break;
// 		if(ret == -1)
// 		{
// 			printf("error...\n");
// 			break;
// 		}
// 		offset += len;
// 		decode_str_size += decode_len;
// 	}
// 	EVP_DecodeFinal(&ctx, decode_str, &decode_len);
// 	decode_str_size += decode_len;
	printf("decode_str:'%s' decode_str_len=%d \n",
		decode_str, decode_str_size);

	ret = memcmp(decode_str, src_str, decode_str_size);

	printf("ret = %d, decode_str_size = %d, src_str_size = %d \n", ret, decode_str_size, src_str_size);
	return 0;

}

int main(int argc, char **argv)
{

	//test_one();

			//!< encode test
	int src_str_size/* = 60*/; 
	unsigned char *src_str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><maps><key name =\"shahai_bind\">ZmFsc2U.</key><key name =\"shahai_crypt_data\">DZya0GizgFpofi40KUu3mrw5GdC3PMOP</key><key name =\"shahai_user_name\">am9uZQ..</key><key name =\"shahai_init_time\">MTM2Njc4NDk5MTI1OQ..</key></maps>";/* = NULL;*/
	int encode_str_size = 0;
	EVP_ENCODE_CTX ctx;
	unsigned char *decode_str =  NULL;
	int decode_str_size = 0;
	int len = 20;   //!< ÿ��decode ���ֽ���  
	int decode_len = 0;
	int offset = 0;
	int ret;



	unsigned char *encode_str = NULL;
	src_str_size = strlen(src_str);


	encode_str = (unsigned char *)malloc( (src_str_size - 1) / 3 * 4 + 4);

	B64Encode(src_str_size, src_str, &encode_str_size, encode_str, NON_STANDARD_BASE64);


	printf("encode_str_size=%d %d encode_str:'%s'  src_str_size = %d \n", encode_str_size, strlen(encode_str), encode_str, src_str_size);


	decode_str = (unsigned char *)malloc(decode_str + 1023);
	
	B64Decode(encode_str_size, encode_str, &decode_str_size, decode_str, NON_STANDARD_BASE64);


	printf("decode_str:'%s' decode_str_len=%d \n", decode_str, decode_str_size);



	ret = memcmp(decode_str, src_str, decode_str_size);

	printf("ret = %d, decode_str_size = %d, src_str_size = %d \n", ret, decode_str_size, src_str_size);

	getchar();

	return 0;

}














