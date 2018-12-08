namespace org.bouncycastle.openpgp.@operator
{
	using S2K = org.bouncycastle.bcpg.S2K;

	public abstract class PBESecretKeyDecryptor
	{
		private char[] passPhrase;
		private PGPDigestCalculatorProvider calculatorProvider;

		public PBESecretKeyDecryptor(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
		{
			this.passPhrase = passPhrase;
			this.calculatorProvider = calculatorProvider;
		}

		public virtual PGPDigestCalculator getChecksumCalculator(int hashAlgorithm)
		{
			return calculatorProvider.get(hashAlgorithm);
		}

		public virtual byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
		{
			return PGPUtil.makeKeyFromPassPhrase(calculatorProvider, keyAlgorithm, s2k, passPhrase);
		}

		public abstract byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen);
	}

}