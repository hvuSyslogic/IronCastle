namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using S2K = org.bouncycastle.bcpg.S2K;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	/// <summary>
	/// JCE based generator for password based encryption (PBE) data protection methods.
	/// </summary>
	public class JcePBEKeyEncryptionMethodGenerator : PBEKeyEncryptionMethodGenerator
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

		/// <summary>
		/// Create a PBE encryption method generator using the provided digest and the default S2K count
		/// for key generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		/// <param name="s2kDigestCalculator"> the digest calculator to use for key calculation. </param>
		public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator) : base(passPhrase, s2kDigestCalculator)
		{
		}

		/// <summary>
		/// Create a PBE encryption method generator using the default SHA-1 digest and the default S2K
		/// count for key generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase) : this(passPhrase, new SHA1PGPDigestCalculator())
		{
		}

		/// <summary>
		/// Create a PBE encryption method generator using the provided calculator and S2K count for key
		/// generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		/// <param name="s2kDigestCalculator"> the digest calculator to use for key calculation. </param>
		/// <param name="s2kCount"> the single byte <seealso cref="S2K"/> count to use. </param>
		public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount) : base(passPhrase, s2kDigestCalculator, s2kCount)
		{
		}

		/// <summary>
		/// Create a PBE encryption method generator using the default SHA-1 digest calculator and a S2K
		/// count other than the default for key generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		/// <param name="s2kCount"> the single byte <seealso cref="S2K"/> count to use. </param>
		public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, int s2kCount) : base(passPhrase, new SHA1PGPDigestCalculator(), s2kCount)
		{
		}

		/// <summary>
		/// Sets the JCE provider to source cryptographic primitives from.
		/// </summary>
		/// <param name="provider"> the JCE provider to use. </param>
		/// <returns> the current generator. </returns>
		public virtual JcePBEKeyEncryptionMethodGenerator setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		/// <summary>
		/// Sets the JCE provider to source cryptographic primitives from.
		/// </summary>
		/// <param name="providerName"> the name of the JCE provider to use. </param>
		/// <returns> the current generator. </returns>
		public virtual JcePBEKeyEncryptionMethodGenerator setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public override PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
		{
			base.setSecureRandom(random);

			return this;
		}

		public override byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
		{
			try
			{
				string cName = PGPUtil.getSymmetricCipherName(encAlgorithm);
				Cipher c = helper.createCipher(cName + "/CFB/NoPadding");
				SecretKey sKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));

				c.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(new byte[c.getBlockSize()]));

				return c.doFinal(sessionInfo, 0, sessionInfo.Length);
			}
			catch (IllegalBlockSizeException e)
			{
				throw new PGPException("illegal block size: " + e.Message, e);
			}
			catch (BadPaddingException e)
			{
				throw new PGPException("bad padding: " + e.Message, e);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new PGPException("IV invalid: " + e.Message, e);
			}
			catch (InvalidKeyException e)
			{
				throw new PGPException("key invalid: " + e.Message, e);
			}
		}
	}

}