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

package krypto.algorithm.lea.impl.kr.re.nsr.crypto;

public abstract class BlockCipherModeAE {

	protected BlockCipher.Mode mode;
	protected BlockCipher engine;

	protected byte[] buffer;
	protected byte[] nonce;
	protected int bufOff;
	protected int blocksize;

	protected int taglen;

	public BlockCipherModeAE(BlockCipher cipher) {
		engine = cipher;
		blocksize = engine.getBlockSize();
		buffer = new byte[blocksize];
	}

	public abstract void init(BlockCipher.Mode mode, byte[] mk, byte[] nonce, int taglen);

	public abstract void updateAAD(byte[] aad);

	public abstract byte[] update(byte[] msg);

	public abstract byte[] doFinal();

	public abstract int getOutputSize(int len);

	public byte[] doFinal(byte[] msg) {
		byte[] out = null;

		if (mode == BlockCipher.Mode.ENCRYPT) {
			byte[] part1 = update(msg);
			byte[] part2 = doFinal();

			int len1 = part1 == null ? 0 : part1.length;
			int len2 = part2 == null ? 0 : part2.length;

			out = new byte[len1 + len2];
			if (part1 != null)
				System.arraycopy(part1, 0, out, 0, len1);

			if (part2 != null)
				System.arraycopy(part2, 0, out, len1, len2);

		} else {
			update(msg);
			out = doFinal();
		}

		return out;
	}
}
