using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cms.jcajce
{


	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using KeyAgreeRecipientIdentifier = org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
	using OriginatorPublicKey = org.bouncycastle.asn1.cms.OriginatorPublicKey;
	using RecipientEncryptedKey = org.bouncycastle.asn1.cms.RecipientEncryptedKey;
	using RecipientKeyIdentifier = org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
	using MQVuserKeyingMaterial = org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using Gost2814789EncryptedKey = org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using GOST28147WrapParameterSpec = org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
	using MQVParameterSpec = org.bouncycastle.jcajce.spec.MQVParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;
	using Arrays = org.bouncycastle.util.Arrays;

	public class JceKeyAgreeRecipientInfoGenerator : KeyAgreeRecipientInfoGenerator
	{
		private SecretKeySizeProvider keySizeProvider = new DefaultSecretKeySizeProvider();

		private List recipientIDs = new ArrayList();
		private List recipientKeys = new ArrayList();
		private PublicKey senderPublicKey;
		private PrivateKey senderPrivateKey;

		private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		private SecureRandom random;
		private KeyPair ephemeralKP;
		private byte[] userKeyingMaterial;

		public JceKeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, PrivateKey senderPrivateKey, PublicKey senderPublicKey, ASN1ObjectIdentifier keyEncryptionOID) : base(keyAgreementOID, SubjectPublicKeyInfo.getInstance(senderPublicKey.getEncoded()), keyEncryptionOID)
		{

			this.senderPublicKey = senderPublicKey;
			this.senderPrivateKey = senderPrivateKey;
		}

		public virtual JceKeyAgreeRecipientInfoGenerator setUserKeyingMaterial(byte[] userKeyingMaterial)
		{
			this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);

			return this;
		}

		public virtual JceKeyAgreeRecipientInfoGenerator setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		public virtual JceKeyAgreeRecipientInfoGenerator setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		public virtual JceKeyAgreeRecipientInfoGenerator setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Add a recipient based on the passed in certificate's public key and its issuer and serial number.
		/// </summary>
		/// <param name="recipientCert"> recipient's certificate </param>
		/// <returns> the current instance. </returns>
		/// <exception cref="CertificateEncodingException">  if the necessary data cannot be extracted from the certificate. </exception>
		public virtual JceKeyAgreeRecipientInfoGenerator addRecipient(X509Certificate recipientCert)
		{
			recipientIDs.add(new KeyAgreeRecipientIdentifier(CMSUtils.getIssuerAndSerialNumber(recipientCert)));
			recipientKeys.add(recipientCert.getPublicKey());

			return this;
		}

		/// <summary>
		/// Add a recipient identified by the passed in subjectKeyID and the for the passed in public key.
		/// </summary>
		/// <param name="subjectKeyID"> identifier actual recipient will use to match the private key. </param>
		/// <param name="publicKey"> the public key for encrypting the secret key. </param>
		/// <returns> the current instance. </returns>
		/// <exception cref="CertificateEncodingException"> </exception>
		public virtual JceKeyAgreeRecipientInfoGenerator addRecipient(byte[] subjectKeyID, PublicKey publicKey)
		{
			recipientIDs.add(new KeyAgreeRecipientIdentifier(new RecipientKeyIdentifier(subjectKeyID)));
			recipientKeys.add(publicKey);

			return this;
		}

		public override ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm, AlgorithmIdentifier keyEncryptionAlgorithm, GenericKey contentEncryptionKey)
		{
			if (recipientIDs.isEmpty())
			{
				throw new CMSException("No recipients associated with generator - use addRecipient()");
			}

			init(keyAgreeAlgorithm.getAlgorithm());

			PrivateKey senderPrivateKey = this.senderPrivateKey;

			ASN1ObjectIdentifier keyAgreementOID = keyAgreeAlgorithm.getAlgorithm();

			ASN1EncodableVector recipientEncryptedKeys = new ASN1EncodableVector();
			for (int i = 0; i != recipientIDs.size(); i++)
			{
				PublicKey recipientPublicKey = (PublicKey)recipientKeys.get(i);
				KeyAgreeRecipientIdentifier karId = (KeyAgreeRecipientIdentifier)recipientIDs.get(i);

				try
				{
					AlgorithmParameterSpec agreementParamSpec;
					ASN1ObjectIdentifier keyEncAlg = keyEncryptionAlgorithm.getAlgorithm();

					if (CMSUtils.isMQV(keyAgreementOID))
					{
						agreementParamSpec = new MQVParameterSpec(ephemeralKP, recipientPublicKey, userKeyingMaterial);
					}
					else if (CMSUtils.isEC(keyAgreementOID))
					{
						byte[] ukmKeyingMaterial = ecc_cms_Generator.generateKDFMaterial(keyEncryptionAlgorithm, keySizeProvider.getKeySize(keyEncAlg), userKeyingMaterial);

						agreementParamSpec = new UserKeyingMaterialSpec(ukmKeyingMaterial);
					}
					else if (CMSUtils.isRFC2631(keyAgreementOID))
					{
						if (userKeyingMaterial != null)
						{
							agreementParamSpec = new UserKeyingMaterialSpec(userKeyingMaterial);
						}
						else
						{
							if (keyAgreementOID.Equals(PKCSObjectIdentifiers_Fields.id_alg_SSDH))
							{
								throw new CMSException("User keying material must be set for static keys.");
							}
							agreementParamSpec = null;
						}
					}
					else if (CMSUtils.isGOST(keyAgreementOID))
					{
						if (userKeyingMaterial != null)
						{
							agreementParamSpec = new UserKeyingMaterialSpec(userKeyingMaterial);
						}
						else
						{
							throw new CMSException("User keying material must be set for static keys.");
						}
					}
					else
					{
						throw new CMSException("Unknown key agreement algorithm: " + keyAgreementOID);
					}

					// Use key agreement to choose a wrap key for this recipient
					KeyAgreement keyAgreement = helper.createKeyAgreement(keyAgreementOID);
					keyAgreement.init(senderPrivateKey, agreementParamSpec, random);
					keyAgreement.doPhase(recipientPublicKey, true);

					SecretKey keyEncryptionKey = keyAgreement.generateSecret(keyEncAlg.getId());

					// Wrap the content encryption key with the agreement key
					Cipher keyEncryptionCipher = helper.createCipher(keyEncAlg);
					ASN1OctetString encryptedKey;

					if (keyEncAlg.Equals(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_None_KeyWrap) || keyEncAlg.Equals(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap))
					{
						keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, new GOST28147WrapParameterSpec(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet, userKeyingMaterial));

						byte[] encKeyBytes = keyEncryptionCipher.wrap(helper.getJceKey(contentEncryptionKey));

						Gost2814789EncryptedKey encKey = new Gost2814789EncryptedKey(Arrays.copyOfRange(encKeyBytes, 0, encKeyBytes.Length - 4), Arrays.copyOfRange(encKeyBytes, encKeyBytes.Length - 4, encKeyBytes.Length));

						encryptedKey = new DEROctetString(encKey.getEncoded(ASN1Encoding_Fields.DER));
					}
					else
					{
						keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, random);

						byte[] encryptedKeyBytes = keyEncryptionCipher.wrap(helper.getJceKey(contentEncryptionKey));

						encryptedKey = new DEROctetString(encryptedKeyBytes);
					}

					recipientEncryptedKeys.add(new RecipientEncryptedKey(karId, encryptedKey));
				}
				catch (GeneralSecurityException e)
				{
					throw new CMSException("cannot perform agreement step: " + e.Message, e);
				}
				catch (IOException e)
				{
					throw new CMSException("unable to encode wrapped key: " + e.Message, e);
				}
			}

			return new DERSequence(recipientEncryptedKeys);
		}

		public override byte[] getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlg)
		{
			init(keyAgreeAlg.getAlgorithm());

			if (ephemeralKP != null)
			{
				OriginatorPublicKey originatorPublicKey = createOriginatorPublicKey(SubjectPublicKeyInfo.getInstance(ephemeralKP.getPublic().getEncoded()));

				try
				{
					if (userKeyingMaterial != null)
					{
						return (new MQVuserKeyingMaterial(originatorPublicKey, new DEROctetString(userKeyingMaterial))).getEncoded();
					}
					else
					{
						return (new MQVuserKeyingMaterial(originatorPublicKey, null)).getEncoded();
					}
				}
				catch (IOException e)
				{
					throw new CMSException("unable to encode user keying material: " + e.Message, e);
				}
			}

			return userKeyingMaterial;
		}

		private void init(ASN1ObjectIdentifier keyAgreementOID)
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

			if (CMSUtils.isMQV(keyAgreementOID))
			{
				if (ephemeralKP == null)
				{
					try
					{
						SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(senderPublicKey.getEncoded());

						AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters(keyAgreementOID);

						ecAlgParams.init(pubInfo.getAlgorithm().getParameters().toASN1Primitive().getEncoded());

						KeyPairGenerator ephemKPG = helper.createKeyPairGenerator(keyAgreementOID);

						ephemKPG.initialize(ecAlgParams.getParameterSpec(typeof(AlgorithmParameterSpec)), random);

						ephemeralKP = ephemKPG.generateKeyPair();
					}
					catch (Exception e)
					{
						throw new CMSException("cannot determine MQV ephemeral key pair parameters from public key: " + e, e);
					}
				}
			}
		}

		private static KeyMaterialGenerator ecc_cms_Generator = new RFC5753KeyMaterialGenerator();
	}
}