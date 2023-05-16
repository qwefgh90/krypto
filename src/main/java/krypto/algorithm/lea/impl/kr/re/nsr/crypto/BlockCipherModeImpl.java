/*
 * According to the KISA website, LEA can be used for product production and sales without any royalty fees related to intellectual property rights.
 *
 * 공식 홈페이지에 따르면, LEA는 지적재산권에 대한 사용료 없이 제품 생산 및 판매와 관련하여 적용할 수 있습니다.
 *
 * Description:
 *
 * It's a copy of a file from a zip file downloaded from
 * https://seed.kisa.or.kr/kisa/Board/20/detailView.do.
 * The zip file is open for public use.
 *
 * Information for LEA
 *   - https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do
 */

package krypto.algorithm.lea.impl.kr.re.nsr.crypto;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher.Mode;

public abstract class BlockCipherModeImpl extends BlockCipherMode {

	protected Mode mode;
	protected BlockCipher engine;

	protected byte[] buffer;
	protected int bufferOffset;
	protected int blocksize;
	protected int blockmask;

	public BlockCipherModeImpl(BlockCipher cipher) {
		engine = cipher;
		blocksize = engine.getBlockSize();
		blockmask = getBlockmask(blocksize);
		buffer = new byte[blocksize];
	}

	@Override
	public byte[] doFinal(byte[] msg) {
		byte[] part1 = update(msg);
		byte[] part2 = doFinal();

		int len1 = part1 == null ? 0 : part1.length;
		int len2 = part2 == null ? 0 : part2.length;

		byte[] out = new byte[len1 + len2];

		if (len1 > 0) {
			System.arraycopy(part1, 0, out, 0, len1);
		}

		if (len2 > 0) {
			System.arraycopy(part2, 0, out, len1, len2);
		}

		return out;
	}

	protected abstract int processBlock(byte[] in, int inOff, byte[] out, int outOff, int length);

	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
		return processBlock(in, inOff, out, outOff, blocksize);
	}

	protected static final int getBlockmask(int blocksize) {
		int mask = 0;

		switch (blocksize) {
		case 8: // 64-bit
			mask = 0xfffffff7;
			break;

		case 16: // 128-bit
			mask = 0xfffffff0;
			break;

		case 32: // 256-bit
			mask = 0xffffffe0;
			break;
		}

		return mask;
	}

	protected static final byte[] clone(byte[] array) {
		if (array == null) {
			return null;
		}

		byte[] clone = new byte[array.length];
		System.arraycopy(array, 0, clone, 0, clone.length);
		return clone;
	}
}
