using System;

namespace org.bouncycastle.@operator.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JceAsymmetricKeyUnwrapper : AsymmetricKeyUnwrapper
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private Map extraMappings = new HashMap();
		private PrivateKey privKey;
		private bool unwrappedKeyMustBeEncodable;

		public JceAsymmetricKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, PrivateKey privKey) : base(algorithmIdentifier)
		{

			this.privKey = privKey;
		}

		public virtual JceAsymmetricKeyUnwrapper setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceAsymmetricKeyUnwrapper setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		/// <summary>
		/// Flag that unwrapping must produce a key that will return a meaningful value from a call to Key.getEncoded().
		/// This is important if you are using a HSM for unwrapping and using a software based provider for
		/// with the unwrapped key. Default value: false.
		/// </summary>
		/// <param name="unwrappedKeyMustBeEncodable"> true if getEncoded() should return key bytes, false if not necessary. </param>
		/// <returns> this recipient. </returns>
		public virtual JceAsymmetricKeyUnwrapper setMustProduceEncodableUnwrappedKey(bool unwrappedKeyMustBeEncodable)
		{
			this.unwrappedKeyMustBeEncodable = unwrappedKeyMustBeEncodable;

			return this;
		}

		/// <summary>
		/// Internally algorithm ids are converted into cipher names using a lookup table. For some providers
		/// the standard lookup table won't work. Use this method to establish a specific mapping from an
		/// algorithm identifier to a specific algorithm.
		/// <para>
		///     For example:
		/// <pre>
		///     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		/// </pre>
		/// </para>
		/// </summary>
		/// <param name="algorithm">  OID of algorithm in recipient. </param>
		/// <param name="algorithmName"> JCE algorithm name to use. </param>
		/// <returns>  the current Unwrapper. </returns>
		public virtual JceAsymmetricKeyUnwrapper setAlgorithmMapping(ASN1ObjectIdentifier algorithm, string algorithmName)
		{
			extraMappings.put(algorithm, algorithmName);

			return this;
		}

		public override GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
		{
			try
			{
				Key sKey = null;

				Cipher keyCipher = helper.createAsymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm(), extraMappings);
				AlgorithmParameters algParams = helper.createAlgorithmParameters(this.getAlgorithmIdentifier());

				try
				{
					if (algParams != null)
					{
						keyCipher.init(Cipher.UNWRAP_MODE, privKey, algParams);
					}
					else
					{
						keyCipher.init(Cipher.UNWRAP_MODE, privKey);
					}

					sKey = keyCipher.unwrap(encryptedKey, helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);

					// check key will work with a software provider.
					if (unwrappedKeyMustBeEncodable)
					{
						try
						{
							byte[] keyBytes = sKey.getEncoded();

							if (keyBytes == null || keyBytes.Length == 0)
							{
								sKey = null;
							}
						}
						catch (Exception)
						{
							sKey = null; // try doing a decrypt
						}
					}
				}
				catch (GeneralSecurityException)
				{ // try decrypt
				}
				catch (IllegalStateException)
				{ // try decrypt
				}
				catch (UnsupportedOperationException)
				{ // try decrypt
				}
				catch (ProviderException)
				{ // try decrypt
				}

				// some providers do not support UNWRAP (this appears to be only for asymmetric algorithms)
				if (sKey == null)
				{
					keyCipher.init(Cipher.DECRYPT_MODE, privKey);
					sKey = new SecretKeySpec(keyCipher.doFinal(encryptedKey), encryptedKeyAlgorithm.getAlgorithm().getId());
				}

				return new JceGenericKey(encryptedKeyAlgorithm, sKey);
			}
			catch (InvalidKeyException e)
			{
				throw new OperatorException("key invalid: " + e.Message, e);
			}
			catch (IllegalBlockSizeException e)
			{
				throw new OperatorException("illegal blocksize: " + e.Message, e);
			}
			catch (BadPaddingException e)
			{
				throw new OperatorException("bad padding: " + e.Message, e);
			}
		}
	}

}