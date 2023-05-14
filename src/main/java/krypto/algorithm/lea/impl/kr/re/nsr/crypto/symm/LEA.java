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

package krypto.algorithm.lea.impl.kr.re.nsr.crypto.symm;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.engine.LeaEngine;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mac.CMac;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.CBCMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.CCMMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.CFBMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.CTRMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.ECBMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.GCMMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.mode.OFBMode;

public class LEA {
	private LEA() {
		throw new AssertionError();
	}

	public static final BlockCipher getEngine() {
		return new LeaEngine();
	}

	public static final class ECB extends ECBMode {
		public ECB() {
			super(getEngine());
		}
	}

	public static final class CBC extends CBCMode {
		public CBC() {
			super(getEngine());
		}
	}

	public static final class CTR extends CTRMode {
		public CTR() {
			super(getEngine());
		}
	}

	public static final class CFB extends CFBMode {
		public CFB() {
			super(getEngine());
		}
	}

	public static final class OFB extends OFBMode {
		public OFB() {
			super(getEngine());
		}
	}

	public static final class CCM extends CCMMode {
		public CCM() {
			super(getEngine());
		}
	}

	public static final class GCM extends GCMMode {
		public GCM() {
			super(getEngine());
		}
	}

	public static final class CMAC extends CMac {
		public CMAC() {
			super(getEngine());
		}
	}

}
