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

/**
 * MAC 구현을 위한 인터페이스
 */
public abstract class Mac {

	/**
	 * 초기화 함수
	 * 
	 * @param key
	 *            비밀키
	 */
	public abstract void init(byte[] key);

	/**
	 * 새로운 메시지에 대한 MAC 계산을 위한 객체 초기화
	 */
	public abstract void reset();

	/**
	 * 메시지 추가
	 * 
	 * @param msg
	 *            추가할 메시지
	 */
	public abstract void update(byte[] msg);

	/**
	 * 마지막 메시지를 포함하여 MAC 계산
	 * 
	 * @param msg
	 *            마지막 메시지
	 * @return MAC 값
	 */
	public abstract byte[] doFinal(byte[] msg);

	/**
	 * 현재까지 추가된 메시지에 대한 MAC 계산
	 * 
	 * @return MAC 값
	 */
	public abstract byte[] doFinal();

}
