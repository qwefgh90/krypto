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

package krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.util.Ops;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher.Mode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipherModeStream;

public class CTRMode extends BlockCipherModeStream {

	private byte[] iv;
	private byte[] ctr;
	private byte[] block;

	public CTRMode(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public String getAlgorithmName() {
		return engine.getAlgorithmName() + "/CTR";
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		this.mode = mode;
		engine.init(Mode.ENCRYPT, mk);

		this.iv = iv.clone();
		ctr = new byte[blocksize];
		block = new byte[blocksize];
		reset();
	}

	@Override
	public void reset() {
		super.reset();
		System.arraycopy(iv, 0, ctr, 0, ctr.length);
	}

	@Override
	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff, int outlen) {
		int length = engine.processBlock(ctr, 0, block, 0);
		addCounter();

		Ops.XOR(out, outOff, in, inOff, block, 0, outlen);

		return length;
	}

	private void addCounter() {
		for (int i = ctr.length - 1; i >= 0; --i) {
			if (++ctr[i] != 0) {
				break;
			}
		}
	}

}
