/*
 * According to the KISA website, The Korea Internet & Security Agency does not charge royalties for intellectual property rights related to the production and sale of products using SEED.
 *
 * 공식 홈페이지에 따르면, 한국인터넷진흥원은 SEED 를 이용한 제품 생산 및 판매와 관련된 지적재산권에 대하여 사용료를 요구하지 않습니다.
 *
 * Copyright (c) 2023 KISA(Korea Information Security Agency). All rights reserved.
 *
 * Description:
 *
 * It's a copy of a file from a zip file downloaded from
 * https://seed.kisa.or.kr/kisa/Board/17/detailView.do.
 * The zip file is open for public use.
 *
 * Information for SEED
 *   - https://seed.kisa.or.kr/kisa/algorithm/EgovSeedInfo.do
 */

package krypto.algorithm.seed.impl.cmac;

public class KISA_SEED_CMAC {
	private static final int BLOCK_SIZE_SEED = 16;
	
	private static void Byte2Word(int[] dst, byte[] src, int srcLen)
    {
        int i = 0;
        int remain = 0;

        for (i = 0; i < srcLen; i++)
        {
            remain = i & 3;

            if (remain == 0)
                dst[i >> 2]  = ((src[i] & 0x0FF) << 24);
            else if (remain == 1)
                dst[i >> 2] ^= ((src[i] & 0x0FF) << 16);
            else if (remain == 2)
                dst[i >> 2] ^= ((src[i] & 0x0FF) <<  8);
            else
                dst[i >> 2] ^= ( src[i] & 0x0FF);
        }
    }
	
	private static void Word2Byte(byte[] dst, int[] src, int srcLen)
    {
        int i = 0;
        int remain = 0;

        for (i = 0; i < srcLen; i++)
        {
            remain = i & 3;

            if (remain == 0)
                dst[i] = (byte)(src[i >> 2] >> 24);
            else if (remain == 1)
                dst[i] = (byte)(src[i >> 2] >> 16);
            else if (remain == 2)
                dst[i] = (byte)(src[i >> 2] >> 8);
            else
                dst[i] = (byte) src[i >> 2];
        }
    }
	
	private void SEED_CMAC_SubkeySched(byte[] sKey)
	{
		int i = 0, carry = (sKey[0] & 0xff) >> 7;

		for (i = 0; i < 15; i++)
			sKey[i] = (byte) (((sKey[i] & 0xff) << 1) | ((sKey[i + 1] & 0xff) >> 7));

		sKey[i] = (byte) ((sKey[i] & 0xff) << 1);

		if (carry != 0)
			sKey[i] ^= 0x87;
	}
	
	public int SEED_Generate_CMAC(byte[] pMAC, int macLen, byte[] pIn, int inLen, byte[] mKey)
	{
		byte[] L = new byte[BLOCK_SIZE_SEED];
		byte[] temp = new byte[BLOCK_SIZE_SEED];
		int[] subKey = new int[BLOCK_SIZE_SEED / 4];
		int[] temp1 = new int[BLOCK_SIZE_SEED / 4];
		int[] rKey = new int[32];
		int blockLen = 0, i = 0, j = 0;
		
		KISA_SEED seed = new KISA_SEED();

		if (macLen > BLOCK_SIZE_SEED)
			return 1;

		seed.SEED_KeySched(mKey, rKey);
		seed.SEED_Encrypt(subKey, subKey, rKey);

		Word2Byte(L, subKey, BLOCK_SIZE_SEED);

		// make K1
		SEED_CMAC_SubkeySched(L);

		if (inLen == 0)
		{
			// make K2
			SEED_CMAC_SubkeySched(L);

			L[0] ^= 0x80;

			Byte2Word(subKey, L, BLOCK_SIZE_SEED);
			seed.SEED_Encrypt(temp1, subKey, rKey);
		}
		else
		{
			// make K2
			SEED_CMAC_SubkeySched(L);

			blockLen = (inLen + BLOCK_SIZE_SEED) / BLOCK_SIZE_SEED;

			for (i = 0; i < blockLen - 1; i++)
			{
				Word2Byte(temp, temp1, BLOCK_SIZE_SEED);
				for (j = 0; j < BLOCK_SIZE_SEED; j++)
					temp[j] ^= pIn[BLOCK_SIZE_SEED * i + j];

				Byte2Word(temp1, temp, BLOCK_SIZE_SEED);

				seed.SEED_Encrypt(temp1, temp1, rKey);
			}

			Word2Byte(temp, temp1, BLOCK_SIZE_SEED);

			for (j = 0; (BLOCK_SIZE_SEED * i + j) < inLen; j++)
				temp[j] ^= pIn[BLOCK_SIZE_SEED * i + j] ^ L[j];
			temp[j] ^= 0x80 ^ L[j];
			for (j += 1; j < BLOCK_SIZE_SEED; j++)
				temp[j] ^= L[j];

			Byte2Word(temp1, temp, BLOCK_SIZE_SEED);

			seed.SEED_Encrypt(temp1, temp1, rKey);
		}

		Word2Byte(temp, temp1, BLOCK_SIZE_SEED);

		for (i = 0; i < macLen; i++)
			pMAC[i] = temp[i];

		return 0;
	}
	
	public int SEED_Verify_CMAC(byte[] pMAC, int macLen, byte[] pIn, int inLen, byte[] mKey)
	{
		byte[] L = new byte[BLOCK_SIZE_SEED];
		byte[] temp = new byte[BLOCK_SIZE_SEED];
		int[] subKey = new int[BLOCK_SIZE_SEED / 4];
		int[] temp1 = new int[BLOCK_SIZE_SEED / 4];
		int[] rKey = new int[32];
		int blockLen = 0, i = 0, j = 0;
		
		KISA_SEED seed = new KISA_SEED();

		if (macLen > BLOCK_SIZE_SEED)
			return 1;

		seed.SEED_KeySched(mKey, rKey);
		seed.SEED_Encrypt(subKey, subKey, rKey);

		Word2Byte(L, subKey, BLOCK_SIZE_SEED);

		// make K1
		SEED_CMAC_SubkeySched(L);

		if (inLen == 0)
		{
			// make K2
			SEED_CMAC_SubkeySched(L);

			L[0] ^= 0x80;

			Byte2Word(subKey, L, BLOCK_SIZE_SEED);
			seed.SEED_Encrypt(temp1, subKey, rKey);
		}
		else
		{
			// make K2
			SEED_CMAC_SubkeySched(L);

			blockLen = (inLen + BLOCK_SIZE_SEED) / BLOCK_SIZE_SEED;

			for (i = 0; i < blockLen - 1; i++)
			{
				Word2Byte(temp, temp1, BLOCK_SIZE_SEED);
				for (j = 0; j < BLOCK_SIZE_SEED; j++)
					temp[j] ^= pIn[BLOCK_SIZE_SEED * i + j];

				Byte2Word(temp1, temp, BLOCK_SIZE_SEED);

				seed.SEED_Encrypt(temp1, temp1, rKey);
			}

			Word2Byte(temp, temp1, BLOCK_SIZE_SEED);

			for (j = 0; (BLOCK_SIZE_SEED * i + j) < inLen; j++)
				temp[j] ^= pIn[BLOCK_SIZE_SEED * i + j] ^ L[j];
			temp[j] ^= 0x80 ^ L[j];
			for (j += 1; j < BLOCK_SIZE_SEED; j++)
				temp[j] ^= L[j];

			Byte2Word(temp1, temp, BLOCK_SIZE_SEED);

			seed.SEED_Encrypt(temp1, temp1, rKey);
		}

		Word2Byte(temp, temp1, BLOCK_SIZE_SEED);

		for (i = 0; i < macLen; i++)
			if (pMAC[i] != temp[i])
				return 1;
		
		return 0;
	}
}
