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

package krypto.algorithm.lea.impl.kr.re.nsr.crypto.mac;

import java.util.Arrays;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.Mac;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.util.Ops;

public class CMac extends Mac {

	private static final byte[] R256 = { (byte) 0x04, (byte) 0x25 };
	private static final byte[] R128 = { (byte) 0x87 };
	private static final byte[] R64 = { (byte) 0x1b };

	private BlockCipher engine;

	private int blocksize;
	private int blkIdx;
	private byte[] block;
	private byte[] mac;

	private byte[] RB;
	private byte k1[], k2[];

	public CMac(BlockCipher cipher) {
		engine = cipher;
	}

	@Override
	public void init(byte[] key) {
		engine.init(BlockCipher.Mode.ENCRYPT, key);

		blkIdx = 0;
		blocksize = engine.getBlockSize();
		block = new byte[blocksize];
		mac = new byte[blocksize];
		k1 = new byte[blocksize];
		k2 = new byte[blocksize];

		selectRB();

		byte[] zero = new byte[blocksize];
		engine.processBlock(zero, 0, zero, 0);
		cmac_subkey(this.k1, zero);
		cmac_subkey(this.k2, this.k1);
	}

	@Override
	public void reset() {
		engine.reset();
		Arrays.fill(block, (byte) 0);
		Arrays.fill(mac, (byte) 0);
		blkIdx = 0;
	}

	@Override
	public void update(byte[] msg) {
		if (msg == null || msg.length == 0) {
			return;
		}

		int len = msg.length;
		int msgOff = 0;
		int gap = blocksize - blkIdx;

		if (len > gap) {
			System.arraycopy(msg, msgOff, block, blkIdx, gap);

			blkIdx = 0;
			len -= gap;
			msgOff += gap;

			while (len > blocksize) {
				Ops.XOR(block, mac);
				engine.processBlock(block, 0, mac, 0);
				System.arraycopy(msg, msgOff, block, 0, blocksize);

				len -= blocksize;
				msgOff += blocksize;
			}

			if (len > 0) {
				Ops.XOR(block, mac);
				engine.processBlock(block, 0, mac, 0);
			}

		}

		if (len > 0) {
			System.arraycopy(msg, msgOff, block, blkIdx, len);
			blkIdx += len;
		}
	}

	@Override
	public byte[] doFinal(byte[] msg) {
		update(msg);
		return doFinal();
	}

	@Override
	public byte[] doFinal() {
		if (blkIdx < blocksize) {
			block[blkIdx] = (byte) 0x80;
			Arrays.fill(block, blkIdx + 1, blocksize, (byte) 0x00);
		}

		Ops.XOR(block, blkIdx == blocksize ? k1 : k2);
		Ops.XOR(block, mac);
		engine.processBlock(block, 0, mac, 0);

		return mac.clone();
	}

	private void selectRB() {
		switch (blocksize) {
		case 8:
			RB = R64;
			break;

		case 16:
			RB = R128;
			break;

		case 32:
			RB = R256;
			break;
		}
	}

	private void cmac_subkey(byte[] new_key, byte[] old_key) {
		System.arraycopy(old_key, 0, new_key, 0, blocksize);
		Ops.shiftLeft(new_key, 1);

		if ((old_key[0] & 0x80) != 0) {
			for (int i = 0; i < RB.length; ++i) {
				new_key[blocksize - RB.length + i] ^= RB[i];
			}
		}
	}
}
