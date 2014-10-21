/** 
 * base64�ӽ���
 *
 */



#ifndef _TS_BASE_H_
#define _TS_BASE_H_

typedef struct evp_Encode_Ctx_st
{
	int num;        /* number saved in a partial encode/decode */
	int length;     	
	/**
	 * The length is either the output line length (in input bytes) or the shortest input line length that is ok. 
	 * Once decoding begins, the length is adjusted up each time a longer line is decoded 
	 */

	unsigned char enc_data[80];   /* data to encode ��������� */
	int line_num;                 /* number read on current line ��ȡ��ǰ���� */
	int expect_nl;
}EVP_ENCODE_CTX;


/* base64���� */
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int	EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out,int *outl, const unsigned char *in, int inl);
int	EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int	EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

/* base64���� */
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl, const unsigned char *in,int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int	EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);



#endif