/*
 * According to the official website, LEA can be used for product production and sales without any royalty fees related to intellectual property rights.
 *
 * 공식 홈페이지에 따르면, LEA는 지적재산권에 대한 사용료 없이 제품 생산 및 판매와 관련하여 적용할 수 있습니다.
 *
 * Description:
 *
 * It's a copy of a public domain work from
 * https://seed.kisa.or.kr/kisa/Board/20/detailView.do
 *
 * Information for LEA
 *   - https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do
 */

package krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode;

import static krypto.algorithm.lea.impl.kr.re.nsr.crypto.util.Ops.*;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher.Mode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipherModeBlock;

public class CBCMode extends BlockCipherModeBlock {

	private byte[] iv;
	private byte[] feedback;

	public CBCMode(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public String getAlgorithmName() {
		return engine.getAlgorithmName() + "/CBC";
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		this.mode = mode;
		engine.init(mode, mk);
		this.iv = clone(iv);

		this.feedback = new byte[blocksize];
		reset();
	}

	@Override
	public void reset() {
		super.reset();
		System.arraycopy(iv, 0, feedback, 0, blocksize);
	}

	@Override
	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff, int outlen) {
		if (outlen != blocksize) {
			throw new IllegalArgumentException("outlen should be " + blocksize + " in " + getAlgorithmName());
		}

		if (mode == Mode.ENCRYPT) {
			return encryptBlock(in, inOff, out, outOff);
		}

		return decryptBlock(in, inOff, out, outOff);
	}

	private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
		if ((inOff + blocksize) > in.length) {
			throw new IllegalStateException("input data too short");
		}

		XOR(feedback, 0, in, inOff, blocksize);

		engine.processBlock(feedback, 0, out, outOff);

		System.arraycopy(out, outOff, feedback, 0, blocksize);

		return blocksize;
	}

	private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
		if ((inOff + blocksize) > in.length) {
			throw new IllegalStateException("input data too short");
		}

		engine.processBlock(in, inOff, out, outOff);

		XOR(out, outOff, feedback, 0, blocksize);

		System.arraycopy(in, inOff, feedback, 0, blocksize);

		return blocksize;
	}

}
