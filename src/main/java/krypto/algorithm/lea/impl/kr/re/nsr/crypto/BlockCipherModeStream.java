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

import java.util.Arrays;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher.Mode;

public abstract class BlockCipherModeStream extends BlockCipherModeImpl {

	public BlockCipherModeStream(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public int getOutputSize(int len) {
		return len + bufferOffset;
	}

	@Override
	public int getUpdateOutputSize(int len) {
		return (len + bufferOffset) & blockmask;
	}

	@Override
	public void init(Mode mode, byte[] mk) {
		throw new IllegalStateException("This init method is not applicable to " + getAlgorithmName());
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		throw new IllegalStateException("This init method is not applicable to " + getAlgorithmName());
	}

	@Override
	public void reset() {
		bufferOffset = 0;
		Arrays.fill(buffer, (byte) 0);
	}

	@Override
	public void setPadding(Padding padding) {
		// Do nothing for this modes
	}

	@Override
	public byte[] update(byte[] msg) {
		if (msg == null) {
			return null;
		}

		int len = msg.length;
		int gap = buffer.length - bufferOffset;
		int inOff = 0;
		int outOff = 0;
		byte[] out = new byte[getUpdateOutputSize(len)];

		if (len >= gap) {
			System.arraycopy(msg, inOff, buffer, bufferOffset, gap);
			outOff += processBlock(buffer, 0, out, outOff);

			bufferOffset = 0;
			len -= gap;
			inOff += gap;

			while (len >= buffer.length) {
				outOff += processBlock(msg, inOff, out, outOff);
				len -= blocksize;
				inOff += blocksize;
			}
		}

		if (len > 0) {
			System.arraycopy(msg, inOff, buffer, bufferOffset, len);
			bufferOffset += len;
			len = 0;
		}

		return out;
	}

	@Override
	public byte[] doFinal() {
		if (bufferOffset == 0) {
			return null;
		}

		byte[] out = new byte[bufferOffset];
		processBlock(buffer, 0, out, 0, bufferOffset);

		return out;
	}

}
