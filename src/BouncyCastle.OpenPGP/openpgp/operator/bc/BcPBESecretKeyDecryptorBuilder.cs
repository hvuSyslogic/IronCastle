namespace org.bouncycastle.openpgp.@operator.bc
{
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;

	public class BcPBESecretKeyDecryptorBuilder
	{
		private PGPDigestCalculatorProvider calculatorProvider;

		public BcPBESecretKeyDecryptorBuilder(PGPDigestCalculatorProvider calculatorProvider)
		{
			this.calculatorProvider = calculatorProvider;
		}

		public virtual PBESecretKeyDecryptor build(char[] passPhrase)
		{
			return new PBESecretKeyDecryptorAnonymousInnerClass(this, passPhrase, calculatorProvider);
		}

		public class PBESecretKeyDecryptorAnonymousInnerClass : PBESecretKeyDecryptor
		{
			private readonly BcPBESecretKeyDecryptorBuilder outerInstance;

			public PBESecretKeyDecryptorAnonymousInnerClass(BcPBESecretKeyDecryptorBuilder outerInstance, char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider) : base(passPhrase, calculatorProvider)
			{
				this.outerInstance = outerInstance;
			}

			public override byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
			{
				try
				{
					BufferedBlockCipher c = BcUtil.createSymmetricKeyWrapper(false, BcImplProvider.createBlockCipher(encAlgorithm), key, iv);

					byte[] @out = new byte[keyLen];
					int outLen = c.processBytes(keyData, keyOff, keyLen, @out, 0);

					outLen += c.doFinal(@out, outLen);

					return @out;
				}
				catch (InvalidCipherTextException e)
				{
					throw new PGPException("decryption failed: " + e.Message, e);
				}
			}
		}
	}

}