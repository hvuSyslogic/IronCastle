using org.bouncycastle.asn1.cryptopro;

using System;

namespace org.bouncycastle.cms.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using Gost2814789EncryptedKey = org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
	using GostR3410KeyTransport = org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
	using GostR3410TransportParameters = org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GOST28147WrapParameterSpec = org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using Arrays = org.bouncycastle.util.Arrays;

	public abstract class JceKeyTransRecipient : KeyTransRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey);
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			contentHelper = helper;
		}

		private PrivateKey recipientKey;

		protected internal EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		protected internal EnvelopedDataHelper contentHelper;
		protected internal Map extraMappings = new HashMap();
		protected internal bool validateKeySize = false;
		protected internal bool unwrappedKeyMustBeEncodable;

		public JceKeyTransRecipient(PrivateKey recipientKey)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.recipientKey = recipientKey;
		}

		/// <summary>
		/// Set the provider to use for key recovery and content processing.
		/// </summary>
		/// <param name="provider"> provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyTransRecipient setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Set the provider to use for key recovery and content processing.
		/// </summary>
		/// <param name="providerName"> the name of the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyTransRecipient setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Internally algorithm ids are converted into cipher names using a lookup table. For some providers
		/// the standard lookup table won't work. Use this method to establish a specific mapping from an
		/// algorithm identifier to a specific algorithm.
		/// <para>
		/// For example:
		/// <pre>
		///     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <param name="algorithm">     OID of algorithm in recipient. </param>
		/// <param name="algorithmName"> JCE algorithm name to use. </param>
		/// <returns> the current Recipient. </returns>
		public virtual JceKeyTransRecipient setAlgorithmMapping(ASN1ObjectIdentifier algorithm, string algorithmName)
		{
			extraMappings.put(algorithm, algorithmName);

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.  If providerName is null a "no provider" search will be
		/// used to satisfy getInstance calls.
		/// </summary>
		/// <param name="provider"> the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyTransRecipient setContentProvider(Provider provider)
		{
			this.contentHelper = CMSUtils.createContentHelper(provider);

			return this;
		}

		/// <summary>
		/// Flag that unwrapping must produce a key that will return a meaningful value from a call to Key.getEncoded().
		/// This is important if you are using a HSM for unwrapping and using a software based provider for
		/// decrypting the content. Default value: false.
		/// </summary>
		/// <param name="unwrappedKeyMustBeEncodable"> true if getEncoded() should return key bytes, false if not necessary. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyTransRecipient setMustProduceEncodableUnwrappedKey(bool unwrappedKeyMustBeEncodable)
		{
			this.unwrappedKeyMustBeEncodable = unwrappedKeyMustBeEncodable;

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.  If providerName is null a "no provider" search will be
		/// used to satisfy getInstance calls.
		/// </summary>
		/// <param name="providerName"> the name of the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyTransRecipient setContentProvider(string providerName)
		{
			this.contentHelper = CMSUtils.createContentHelper(providerName);

			return this;
		}

		/// <summary>
		/// Set validation of retrieved key sizes against the algorithm parameters for the encrypted key where possible - default is off.
		/// <para>
		/// This setting will not have any affect if the encryption algorithm in the recipient does not specify a particular key size, or
		/// if the unwrapper is a HSM and the byte encoding of the unwrapped secret key is not available.
		/// </para>
		/// </summary>
		/// <param name="doValidate"> true if unwrapped key's should be validated against the content encryption algorithm, false otherwise. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyTransRecipient setKeySizeValidation(bool doValidate)
		{
			this.validateKeySize = doValidate;

			return this;
		}

		public virtual Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
		{
			if (CMSUtils.isGOST(keyEncryptionAlgorithm.getAlgorithm()))
			{
				try
				{
					GostR3410KeyTransport transport = GostR3410KeyTransport.getInstance(encryptedEncryptionKey);

					GostR3410TransportParameters transParams = transport.getTransportParameters();

					KeyFactory keyFactory = helper.createKeyFactory(keyEncryptionAlgorithm.getAlgorithm());

					PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(transParams.getEphemeralPublicKey().getEncoded()));

					KeyAgreement agreement = helper.createKeyAgreement(keyEncryptionAlgorithm.getAlgorithm());

					agreement.init(recipientKey, new UserKeyingMaterialSpec(transParams.getUkm()));

					agreement.doPhase(pubKey, true);

					SecretKey key = agreement.generateSecret(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap.getId());

					Cipher keyCipher = helper.createCipher(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap);

					keyCipher.init(Cipher.UNWRAP_MODE, key, new GOST28147WrapParameterSpec(transParams.getEncryptionParamSet(), transParams.getUkm()));

					Gost2814789EncryptedKey encKey = transport.getSessionEncryptedKey();

					return keyCipher.unwrap(Arrays.concatenate(encKey.getEncryptedKey(), encKey.getMacKey()), helper.getBaseCipherName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
				}
				catch (Exception e)
				{
					throw new CMSException("exception unwrapping key: " + e.Message, e);
				}
			}
			else
			{
				JceAsymmetricKeyUnwrapper unwrapper = helper.createAsymmetricUnwrapper(keyEncryptionAlgorithm, recipientKey).setMustProduceEncodableUnwrappedKey(unwrappedKeyMustBeEncodable);

				if (!extraMappings.isEmpty())
				{
					for (Iterator it = extraMappings.keySet().iterator(); it.hasNext();)
					{
						ASN1ObjectIdentifier algorithm = (ASN1ObjectIdentifier)it.next();

						unwrapper.setAlgorithmMapping(algorithm, (string)extraMappings.get(algorithm));
					}
				}

				try
				{
					Key key = helper.getJceKey(encryptedKeyAlgorithm.getAlgorithm(), unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));

					if (validateKeySize)
					{
						helper.keySizeCheck(encryptedKeyAlgorithm, key);
					}

					return key;
				}
				catch (OperatorException e)
				{
					throw new CMSException("exception unwrapping key: " + e.Message, e);
				}
			}
		}
	}

}