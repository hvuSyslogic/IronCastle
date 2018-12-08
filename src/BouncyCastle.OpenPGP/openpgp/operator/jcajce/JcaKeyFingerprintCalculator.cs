namespace org.bouncycastle.openpgp.@operator.jcajce
{

	using BCPGKey = org.bouncycastle.bcpg.BCPGKey;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSAPublicBCPGKey = org.bouncycastle.bcpg.RSAPublicBCPGKey;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaKeyFingerprintCalculator : KeyFingerPrintCalculator
	{
		private readonly JcaJceHelper helper;

		/// <summary>
		/// Base Constructor - use the JCA defaults.
		/// </summary>
		public JcaKeyFingerprintCalculator() : this(new DefaultJcaJceHelper())
		{
		}

		private JcaKeyFingerprintCalculator(JcaJceHelper helper)
		{
			this.helper = helper;
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="provider"> the JCA provider to use. </param>
		/// <returns> a new JceKeyFingerprintCalculator supported by the passed in provider. </returns>
		public virtual JcaKeyFingerprintCalculator setProvider(Provider provider)
		{
			return new JcaKeyFingerprintCalculator(new ProviderJcaJceHelper(provider));
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="providerName"> the name of the JCA provider to use. </param>
		/// <returns> a new JceKeyFingerprintCalculator supported by the passed in named provider. </returns>
		public virtual JcaKeyFingerprintCalculator setProvider(string providerName)
		{
			return new JcaKeyFingerprintCalculator(new NamedJcaJceHelper(providerName));
		}

		public virtual byte[] calculateFingerprint(PublicKeyPacket publicPk)
		{
			BCPGKey key = publicPk.getKey();

			if (publicPk.getVersion() <= 3)
			{
				RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

				try
				{
					MessageDigest digest = helper.createDigest("MD5");

					byte[] bytes = (new MPInteger(rK.getModulus())).getEncoded();
					digest.update(bytes, 2, bytes.Length - 2);

					bytes = (new MPInteger(rK.getPublicExponent())).getEncoded();
					digest.update(bytes, 2, bytes.Length - 2);

					return digest.digest();
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new PGPException("can't find MD5", e);
				}
				catch (NoSuchProviderException e)
				{
					throw new PGPException("can't find MD5", e);
				}
				catch (IOException e)
				{
					throw new PGPException("can't encode key components: " + e.Message, e);
				}
			}
			else
			{
				try
				{
					byte[] kBytes = publicPk.getEncodedContents();

					MessageDigest digest = helper.createDigest("SHA1");

					digest.update(unchecked((byte)0x99));
					digest.update((byte)(kBytes.Length >> 8));
					digest.update((byte)kBytes.Length);
					digest.update(kBytes);

					return digest.digest();
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new PGPException("can't find SHA1", e);
				}
				catch (NoSuchProviderException e)
				{
					throw new PGPException("can't find SHA1", e);
				}
				catch (IOException e)
				{
					throw new PGPException("can't encode key components: " + e.Message, e);
				}
			}
		}
	}

}