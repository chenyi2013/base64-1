#include "ts_base.h"



/* die if we have to */
void OpenSSLDie(const char *file,int line,const char *assertion);
#define OPENSSL_assert(e)       (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e),1))


#ifndef CHARSET_EBCDIC
#define conv_bin2ascii(a)	(data_bin2ascii[(a)&0x3f])  // 0x3f = 0011 1111
#define conv_ascii2bin(a)	(data_ascii2bin[(a)&0x7f])  // 0x7f = 0111 1111
#else
/* We assume that PEM encoded files are EBCDIC files
 * (i.e., printable text files). Convert them here while decoding.
 * When encoding, output is EBCDIC (text) format again.
 * (No need for conversion in the conv_bin2ascii macro, as the
 * underlying textstring data_bin2ascii[] is already EBCDIC)
 */
#define conv_bin2ascii(a)	(data_bin2ascii[(a)&0x3f])
#define conv_ascii2bin(a)	(data_ascii2bin[os_toascii[a]&0x7f])
#endif


/* 64 char lines
 * pad input with 0
 * left over chars are set to =
 * 1 byte  => xx==
 * 2 bytes => xxx=
 * 3 bytes => xxxx
 */
#define BIN_PER_LINE    (64/4*3)
#define CHUNKS_PER_LINE (64/4)
#define CHAR_PER_LINE   (64+1)

static const unsigned char data_bin2ascii[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz0123456789+/";

/* 0xF0 is a EOLN
 * 0xF1 is ignore but next needs to be 0xF0 (for \r\n processing).
 * 0xF2 is EOF
 * 0xE0 is ignore at start of line.
 * 0xFF is error
 */
#define B64_EOLN		0xF0  //  1111 0000
#define B64_CR			0xF1  //  1111 0001
#define B64_EOF			0xF2  //  1111 0010
#define B64_WS			0xE0  //  1110 0000
#define B64_ERROR       	0xFF   //  1111 1111
#define B64_NOT_BASE64(a)	(((a)|0x13) == 0xF3)  // 0x13 = 0001 0011    0xF3 = 1111 0011

static const unsigned char data_ascii2bin[128]={
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xE0,0xF0,0xFF,0xFF,0xF1,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xE0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0x3E,0xFF,0xF2,0xFF,0x3F,
	0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,
	0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
	0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,
	0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
	0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
	0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
	0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
	0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
	0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,
	};


// 该函数初始化一个用来进行base64编码的结构
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx)
{
	ctx->length=48;
	ctx->num=0;
	ctx->line_num=0;
}

/** 
 * 该函数将参数in里面的inl个数据拷贝到结构体ctx里面,
 * 如果结构体里面有数据，就同时将结构体里面的数据进行BASE64编码并输出到参数out指向的缓存里面，输出数据的长度保存在outl里面。
 * 注意，在第一次调用本函数的时候，虽然往结构体里面拷贝数据了，
 * 但是结构体ctx里面开始是没有输入数据存在并且输入数据长度不超出ctx内部存储数据的最长限制，就不会有任何数据被进行BASE64编码，
 * 也就是说，不会有任何数据输出；
 * 但是如果输入数据长度比内部存储的数据长，那么就会输出部分经过BASE64编码的数据。数据输出总是在下一层输入前完成的。
 *
 */
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
	int i, j;
	unsigned int total = 0;

	*outl = 0;
	if(0 == inl)
		return ;
	OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
	if((ctx->num + inl) < ctx->length)
	{
		memcpy(&(ctx->enc_data[ctx->num]), in, inl);
		ctx->num += inl;
		return;
	}
	if(0 != ctx->num)
	{
		i = ctx->length - ctx->num;
		memcpy(&(ctx->enc_data[ctx->num]), in, i);
		in += i;
		inl -= i;
		j = EVP_EncodeBlock(out, ctx->enc_data, ctx->length);
		ctx->num = 0;
		out += j;
		*(out++) = '\n';
		*out = '\0';
		total = j + 1;
	}
	while(inl >= ctx->length)
	{
		j = EVP_EncodeBlock(out, in, ctx->length);
		in += ctx->length;
		inl -= ctx->length;
		out += j;
		*(out++) = '\n';
		*out = '\0';
		total += j + 1;
	}
	if(0 != inl)
		memcpy(&(ctx->enc_data[0]), in, inl);
	ctx->num = inl;
	*outl = total;
}

/** 
 * 该函数将结构体ctx里面剩余数据进行BASE64编码并写入到参数out里面去，输出数据的长度保存在outl里面。
 *
 */
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
	unsigned int ret = 0;
	if( 0 != ctx->num)
	{
		ret = EVP_EncodeBlock(out, ctx->enc_data, ctx->num);
		out[ret++] = '\n';
		out[ret] = '\0';
		ctx->num = 0;
	}
	*outl = ret;
}



/** 
 * 功能:该函数将参数f里面的字符串里面的n个字节的字符串进行BASE64编码并输出到参数t里面。返回编码后数据的字节长度。
 *
 */
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen)
{
	int i, ret = 0;
	unsigned long l;

	for (i = dlen; i > 0; i-=3)
	{
		if (i >= 3)
		{
			l = (((unsigned long)f[0])<<16L)|
				(((unsigned long)f[1])<< 8L)|f[2]; 
			*(t++)=conv_bin2ascii(l >> 18L);
			*(t++)=conv_bin2ascii(l >> 12L);
			*(t++)=conv_bin2ascii(l >>  6L);
			*(t++)=conv_bin2ascii(l       );
		}
		else
		{
			l = ((unsigned long)f[0]) << 16L;
			if (i == 2)
				l |= ((unsigned long)f[1] << 8L);

			*(t++) = conv_bin2ascii(l >> 18L);
			*(t++) = conv_bin2ascii(l >> 12L);
			*(t++) = (i == 1)?'=':conv_bin2ascii(l >> 6L);
			*(t++) = '=';
		}
		ret += 4;
		f += 3;
	}
	*t = '\0';
	return(ret);
}


/* base64解码 */
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx)
{
	ctx->length = 30;
	ctx->num = 0;
	ctx->line_num = 0;
	ctx->expect_nl = 0;
}


/** 
 *  功能: 该函数将参数in里面inl字节的数据拷贝到结构体ctx里面。
 *  如果结构体里面已经有数据，那么这些数据就会先进行BASE64解码，然后输出到参数out指向的内存中，输出的字节数保存在参数outl里面。
 *  输入数据为满行的数据时，返回为1；如果输入数据是最后一行数据的时候，返回0；返回－1则表明出错了。
 *  -1 for error;  0 for last line;  1 for full line
 */
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
	     const unsigned char *in, int inl)
	{
	int seof= -1,eof=0,rv= -1,ret=0,i,v,tmp,n,ln,exp_nl;
	unsigned char *d;

	n=ctx->num;
	d=ctx->enc_data;
	ln=ctx->line_num;
	exp_nl=ctx->expect_nl;

	/* last line of input. */
	if ((inl == 0) || ((n == 0) && (conv_ascii2bin(in[0]) == B64_EOF)))
		{ rv=0; goto end; }
		
	/* We parse the input data */
	for (i=0; i<inl; i++)
		{
		/* If the current line is > 80 characters, scream alot */
		if (ln >= 80) { rv= -1; goto end; }

		/* Get char and put it into the buffer */
		tmp= *(in++);
		v=conv_ascii2bin(tmp);
		/* only save the good data :-) */
		if (!B64_NOT_BASE64(v))
			{
			OPENSSL_assert(n < (int)sizeof(ctx->enc_data));
			d[n++]=tmp;
			ln++;
			}
		else if (v == B64_ERROR)
			{
			rv= -1;
			goto end;
			}

		/* have we seen a '=' which is 'definitly' the last
		 * input line.  seof will point to the character that
		 * holds it. and eof will hold how many characters to
		 * chop off. */
		if (tmp == '=')
			{
			if (seof == -1) seof=n;
			eof++;
			}

		if (v == B64_CR)
			{
			ln = 0;
			if (exp_nl)
				continue;
			}

		/* eoln */
		if (v == B64_EOLN)
			{
			ln=0;
			if (exp_nl)
				{
				exp_nl=0;
				continue;
				}
			}
		exp_nl=0;

		/* If we are at the end of input and it looks like a
		 * line, process it. */
		if (((i+1) == inl) && (((n&3) == 0) || eof))
			{
			v=B64_EOF;
			/* In case things were given us in really small
			   records (so two '=' were given in separate
			   updates), eof may contain the incorrect number
			   of ending bytes to skip, so let's redo the count */
			eof = 0;
			if (d[n-1] == '=') eof++;
			if (d[n-2] == '=') eof++;
			/* There will never be more than two '=' */
			}

		if ((v == B64_EOF && (n&3) == 0) || (n >= 64))
			{
			/* This is needed to work correctly on 64 byte input
			 * lines.  We process the line and then need to
			 * accept the '\n' */
			if ((v != B64_EOF) && (n >= 64)) exp_nl=1;
			if (n > 0)
				{
				v=EVP_DecodeBlock(out,d,n);
				n=0;
				if (v < 0) { rv=0; goto end; }
				ret+=(v-eof);
				}
			else
				{
				eof=1;
				v=0;
				}

			/* This is the case where we have had a short
			 * but valid input line */
			if ((v < ctx->length) && eof)
				{
				rv=0;
				goto end;
				}
			else
				ctx->length=v;

			if (seof >= 0) { rv=0; goto end; }
			out+=v;
			}
		}
	rv=1;
end:
	*outl=ret;
	ctx->num=n;
	ctx->line_num=ln;
	ctx->expect_nl=exp_nl;
	return(rv);
	}


/** 
 * 功能：该函数将字符串f中的n字节数据进行BASE64解码，并输出到t指向的内存中，输出数据长度为outl。成功返回解码的数据长度，返回返回－1。
 * 参数：
 * t：接收解码后的数据缓冲区; f：解码前的数据; n：解码前的数据长度。
 */
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n)
{
	int i, ret = 0, a, b, c, d;
	unsigned long l;

	/* trim white space from the start of the line.从开始行裁减空格  ??? */
	while ((B64_WS == conv_ascii2bin(*f)) && (n > 0))  //  B64_WS == 1110 0000
	{
		f++;
		n--;
	}

	/* strip off stuff at the end of the line ascii2bin values B64_WS, B64_EOLN, B64_EOLN and B64_EOF */
	while((n > 3) && (B64_NOT_BASE64(conv_ascii2bin(f[n - 1]))))
		n--;

	if(0 != n%4)
		return -1;

	for (i = 0; i < n; i += 4)
	{
		a = conv_ascii2bin(*(f++));
		b = conv_ascii2bin(*(f++));
		c = conv_ascii2bin(*(f++));
		d = conv_ascii2bin(*(f++));
		if((a & 0x80) || (b & 0x80) || (c & 0x80) || (d & 0x80))
			return -1;
		l = ((((unsigned long)a) << 18L) | (((unsigned long)b) << 12L) | (((unsigned long)c) << 6L) | (((unsigned long)d)));
		*(t++) = (unsigned char)(l >> 16L) & 0xff;
		*(t++) = (unsigned char)(l >>  8L) & 0xff;
		*(t++) = (unsigned char)(l       ) & 0xff;
		ret += 3;
	}
	return ret;
}

/** 
 * 功能：该函数将结构体ctx里面剩余的数据进行BASE64解码并输出到参数out指向的内存中，输出数据长度为outl字节。
 * 成功返回1，否则返回－1。
 */
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
	int i;
	
	*outl = 0;
	if(0 != ctx->num)
	{
		i = EVP_DecodeBlock(out, ctx->enc_data, ctx->num);
		if (i < 0)
			return -1;
		ctx->num = 0;
		*outl = i;
		return 1;
	}
	else
		return 1;

}





/** 
 * base64 编码
 * iOriLen:编码前的数据长度
 * strOrdData:编码前数据
 * iDstLen:编码后的数据长度
 * strDstData:存放编码后的数据缓冲区
 * B64Encode(32, out, outLen, (unsigned char*)szDstData);
 * standardt:标准base64编码标志; 标准:standard_not = STANDARD_BASE64 
 */
int B64Encode(int iOriLen, unsigned char* strOrdData, int *iDstLen, unsigned char* strDstData, unsigned int standard)
{
	int k;
	int iOutLen;
	int index;
	int len;

	EVP_ENCODE_CTX ctx;

	EVP_EncodeInit(&ctx);
	EVP_EncodeUpdate(&ctx, (unsigned char *)strDstData, (int *)&iOutLen, (unsigned char *)strOrdData,(int)iOriLen);

	EVP_EncodeFinal(&ctx, (unsigned char *)&strDstData[iOutLen], &k);


	iOutLen += k;
	*iDstLen = iOutLen;
	if(STANDARD_BASE64 == standard)
		return 0;

	for (index = 0; index < iOutLen; index++)
	{
		if(strDstData[index] == '+')
			strDstData[index] = '*';
		if(strDstData[index] == '/')
			strDstData[index] = '-';
		if(strDstData[index] == '=')
		{
			strDstData[index] = '.';
		}
	}

	printf("iOutLen ==--------==> %d  \n", iOutLen);
	printf("strDstData[index - 3] %c | %c | %c \n", strDstData[index - 3], strDstData[index - 2], strDstData[index - 1]);
	
	return 0;
}



/** 
 * base64 解码
 * iOriLen:解码前的数据长度
 * strOrdData:解码前数据
 * iDstLen:解码后的数据长度
 * strDstData:解码编码后的数据缓冲区
 * standardt:标准base64解码标志; 标准:standard_not = STANDARD_BASE64 
 */
int B64Decode(int iOriLen, unsigned char *strOrdData, int *iDstLen, unsigned char* strDstData, unsigned int standard)
{


	int iRet;
	int k;
	int index;
	char strTemp[90];
	unsigned char *pTemp = strOrdData;
	int iLeftLen = iOriLen;
	int iInLen;
	unsigned char *pTemp1 = strDstData;
	int iInputLen = 64;
	int iOutLen = 0;

	EVP_ENCODE_CTX ctx;
	EVP_DecodeInit(&ctx);

	if(STANDARD_BASE64 == standard)
		return 0;

	for (index = 0; index < iOriLen; index++)
	{
		if(strOrdData[index] == '*')
			strOrdData[index] = '+';
		if(strOrdData[index] == '-')
			strOrdData[index] = '/';
		if(strOrdData[index] == '.')
		{
			strOrdData[index] = '=';
		}
	}

	while(iLeftLen > 0)
	{
		memset(strTemp, 0, sizeof(strTemp));
		if(iLeftLen > iInputLen)
		{
			memcpy(strTemp, pTemp, iInputLen);
			strcat(strTemp, "\n");
			pTemp += iInputLen;
			iLeftLen = iLeftLen - iInputLen;
			iInLen = iInputLen + 1;
		}
		else
		{
			memcpy(strTemp, pTemp, iLeftLen);
			strcat(strTemp, "\n");
			pTemp += iLeftLen;
			iInLen = iLeftLen + 1;
			iLeftLen = 0;
		}
		iRet = EVP_DecodeUpdate(&ctx, pTemp1, &k, (unsigned char *)strTemp, iInLen);
		pTemp1 += k;
		iOutLen += k;
		if (iRet < 0)
		{
			return -1;
		}
	}
	iRet = EVP_DecodeFinal(&ctx, pTemp1, &k);
	if (iRet < 0)
	{
		return -1;
	}

	iOutLen += k;
	*iDstLen = iOutLen;
	return 0;
}