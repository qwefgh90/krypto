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

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.util.Ops;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher.Mode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipherModeStream;

// DONE: block vs buffer
public class CFBMode extends BlockCipherModeStream {

	private byte[] iv;
	private byte[] block;
	private byte[] feedback;

	public CFBMode(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public String getAlgorithmName() {
		return engine.getAlgorithmName() + "/CFB";
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		this.mode = mode;
		engine.init(Mode.ENCRYPT, mk);

		this.iv = iv.clone();
		block = new byte[blocksize];
		feedback = new byte[blocksize];
		reset();
	}

	@Override
	public void reset() {
		super.reset();
		System.arraycopy(iv, 0, feedback, 0, blocksize);
	}

	@Override
	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff, int outlen) {
		int length = engine.processBlock(feedback, 0, block, 0);
		Ops.XOR(out, outOff, in, inOff, block, 0, outlen);

		if (mode == Mode.ENCRYPT) {
			System.arraycopy(out, outOff, feedback, 0, blocksize);

		} else {
			System.arraycopy(in, inOff, feedback, 0, blocksize);
		}

		return length;
	}

}
