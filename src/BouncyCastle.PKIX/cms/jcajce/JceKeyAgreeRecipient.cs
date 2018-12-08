using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cms.jcajce
{


	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using ECCCMSSharedInfo = org.bouncycastle.asn1.cms.ecc.ECCCMSSharedInfo;
	using MQVuserKeyingMaterial = org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using Gost2814789EncryptedKey = org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
	using Gost2814789KeyWrapParameters = org.bouncycastle.asn1.cryptopro.Gost2814789KeyWrapParameters;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using GOST28147WrapParameterSpec = org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
	using MQVParameterSpec = org.bouncycastle.jcajce.spec.MQVParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;

	public abstract class JceKeyAgreeRecipient : KeyAgreeRecipient
	{
		public abstract RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, SubjectPublicKeyInfo senderPublicKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey);
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			contentHelper = helper;
		}

		private static readonly Set possibleOldMessages = new HashSet();

		static JceKeyAgreeRecipient()
		{
			possibleOldMessages.add(X9ObjectIdentifiers_Fields.dhSinglePass_stdDH_sha1kdf_scheme);
			possibleOldMessages.add(X9ObjectIdentifiers_Fields.mqvSinglePass_sha1kdf_scheme);
		}

		private PrivateKey recipientKey;
		protected internal EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		protected internal EnvelopedDataHelper contentHelper;
		private SecretKeySizeProvider keySizeProvider = new DefaultSecretKeySizeProvider();


		public JceKeyAgreeRecipient(PrivateKey recipientKey)
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
		public virtual JceKeyAgreeRecipient setProvider(Provider provider)
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
		public virtual JceKeyAgreeRecipient setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing.  If providerName is null a "no provider" search will be
		///  used to satisfy getInstance calls.
		/// </summary>
		/// <param name="provider"> the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyAgreeRecipient setContentProvider(Provider provider)
		{
			this.contentHelper = CMSUtils.createContentHelper(provider);

			return this;
		}

		/// <summary>
		/// Set the provider to use for content processing. If providerName is null a "no provider" search will be
		/// used to satisfy getInstance calls.
		/// </summary>
		/// <param name="providerName"> the name of the provider to use. </param>
		/// <returns> this recipient. </returns>
		public virtual JceKeyAgreeRecipient setContentProvider(string providerName)
		{
			this.contentHelper = CMSUtils.createContentHelper(providerName);

			return this;
		}

		private SecretKey calculateAgreedWrapKey(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier wrapAlg, PublicKey senderPublicKey, ASN1OctetString userKeyingMaterial, PrivateKey receiverPrivateKey, KeyMaterialGenerator kmGen)
		{
			if (CMSUtils.isMQV(keyEncAlg.getAlgorithm()))
			{
				MQVuserKeyingMaterial ukm = MQVuserKeyingMaterial.getInstance(userKeyingMaterial.getOctets());

				SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(getPrivateKeyAlgorithmIdentifier(), ukm.getEphemeralPublicKey().getPublicKey().getBytes());

				X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());
				KeyFactory fact = helper.createKeyFactory(keyEncAlg.getAlgorithm());
				PublicKey ephemeralKey = fact.generatePublic(pubSpec);

				KeyAgreement agreement = helper.createKeyAgreement(keyEncAlg.getAlgorithm());

				byte[] ukmKeyingMaterial = (ukm.getAddedukm() != null) ? ukm.getAddedukm().getOctets() : null;
				if (kmGen == old_ecc_cms_Generator)
				{
					ukmKeyingMaterial = old_ecc_cms_Generator.generateKDFMaterial(wrapAlg, keySizeProvider.getKeySize(wrapAlg), ukmKeyingMaterial);
				}

				agreement.init(receiverPrivateKey, new MQVParameterSpec(receiverPrivateKey, ephemeralKey, ukmKeyingMaterial));
				agreement.doPhase(senderPublicKey, true);

				return agreement.generateSecret(wrapAlg.getAlgorithm().getId());
			}
			else
			{
				KeyAgreement agreement = helper.createKeyAgreement(keyEncAlg.getAlgorithm());

				UserKeyingMaterialSpec userKeyingMaterialSpec = null;

				if (CMSUtils.isEC(keyEncAlg.getAlgorithm()))
				{
					if (userKeyingMaterial != null)
					{
						byte[] ukmKeyingMaterial = kmGen.generateKDFMaterial(wrapAlg, keySizeProvider.getKeySize(wrapAlg), userKeyingMaterial.getOctets());

						userKeyingMaterialSpec = new UserKeyingMaterialSpec(ukmKeyingMaterial);
					}
					else
					{
						byte[] ukmKeyingMaterial = kmGen.generateKDFMaterial(wrapAlg, keySizeProvider.getKeySize(wrapAlg), null);

						userKeyingMaterialSpec = new UserKeyingMaterialSpec(ukmKeyingMaterial);
					}
				}
				else if (CMSUtils.isRFC2631(keyEncAlg.getAlgorithm()))
				{
					if (userKeyingMaterial != null)
					{
						userKeyingMaterialSpec = new UserKeyingMaterialSpec(userKeyingMaterial.getOctets());
					}
				}
				else if (CMSUtils.isGOST(keyEncAlg.getAlgorithm()))
				{
					if (userKeyingMaterial != null)
					{
						userKeyingMaterialSpec = new UserKeyingMaterialSpec(userKeyingMaterial.getOctets());
					}
				}
				else
				{
					throw new CMSException("Unknown key agreement algorithm: " + keyEncAlg.getAlgorithm());
				}

				agreement.init(receiverPrivateKey, userKeyingMaterialSpec);

				agreement.doPhase(senderPublicKey, true);

				return agreement.generateSecret(wrapAlg.getAlgorithm().getId());
			}
		}

		private Key unwrapSessionKey(ASN1ObjectIdentifier wrapAlg, SecretKey agreedKey, ASN1ObjectIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			Cipher keyCipher = helper.createCipher(wrapAlg);
			keyCipher.init(Cipher.UNWRAP_MODE, agreedKey);
			return keyCipher.unwrap(encryptedContentEncryptionKey, helper.getBaseCipherName(contentEncryptionAlgorithm), Cipher.SECRET_KEY);
		}

		public virtual Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, SubjectPublicKeyInfo senderKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentEncryptionKey)
		{
			try
			{
				AlgorithmIdentifier wrapAlg = AlgorithmIdentifier.getInstance(keyEncryptionAlgorithm.getParameters());

				X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(senderKey.getEncoded());
				KeyFactory fact = helper.createKeyFactory(senderKey.getAlgorithm().getAlgorithm());
				PublicKey senderPublicKey = fact.generatePublic(pubSpec);

				try
				{
					SecretKey agreedWrapKey = calculateAgreedWrapKey(keyEncryptionAlgorithm, wrapAlg, senderPublicKey, userKeyingMaterial, recipientKey, ecc_cms_Generator);

					if (wrapAlg.getAlgorithm().Equals(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_None_KeyWrap) || wrapAlg.getAlgorithm().Equals(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap))
					{
						Gost2814789EncryptedKey encKey = Gost2814789EncryptedKey.getInstance(encryptedContentEncryptionKey);
						Gost2814789KeyWrapParameters wrapParams = Gost2814789KeyWrapParameters.getInstance(wrapAlg.getParameters());

						Cipher keyCipher = helper.createCipher(wrapAlg.getAlgorithm());

						keyCipher.init(Cipher.UNWRAP_MODE, agreedWrapKey, new GOST28147WrapParameterSpec(wrapParams.getEncryptionParamSet(), userKeyingMaterial.getOctets()));

						return keyCipher.unwrap(Arrays.concatenate(encKey.getEncryptedKey(), encKey.getMacKey()), helper.getBaseCipherName(contentEncryptionAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
					}

					return unwrapSessionKey(wrapAlg.getAlgorithm(), agreedWrapKey, contentEncryptionAlgorithm.getAlgorithm(), encryptedContentEncryptionKey);
				}
				catch (InvalidKeyException e)
				{
					// might be a pre-RFC 5753 message
					if (possibleOldMessages.contains(keyEncryptionAlgorithm.getAlgorithm()))
					{
						SecretKey agreedWrapKey = calculateAgreedWrapKey(keyEncryptionAlgorithm, wrapAlg, senderPublicKey, userKeyingMaterial, recipientKey, old_ecc_cms_Generator);

						return unwrapSessionKey(wrapAlg.getAlgorithm(), agreedWrapKey, contentEncryptionAlgorithm.getAlgorithm(), encryptedContentEncryptionKey);
					}
					throw e;
				}
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new CMSException("can't find algorithm.", e);
			}
			catch (InvalidKeyException e)
			{
				throw new CMSException("key invalid in message.", e);
			}
			catch (InvalidKeySpecException e)
			{
				throw new CMSException("originator key spec invalid.", e);
			}
			catch (NoSuchPaddingException e)
			{
				throw new CMSException("required padding not supported.", e);
			}
			catch (Exception e)
			{
				throw new CMSException("originator key invalid.", e);
			}
		}

		public virtual AlgorithmIdentifier getPrivateKeyAlgorithmIdentifier()
		{
			return PrivateKeyInfo.getInstance(recipientKey.getEncoded()).getPrivateKeyAlgorithm();
		}

		private static KeyMaterialGenerator old_ecc_cms_Generator = new KeyMaterialGeneratorAnonymousInnerClass();

		public class KeyMaterialGeneratorAnonymousInnerClass : KeyMaterialGenerator
		{
			public byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
			{
				ECCCMSSharedInfo eccInfo;

				// this isn't correct with AES and RFC 5753, but we have messages predating it...
				eccInfo = new ECCCMSSharedInfo(new AlgorithmIdentifier(keyAlgorithm.getAlgorithm(), DERNull.INSTANCE), userKeyMaterialParameters, Pack.intToBigEndian(keySize));

				try
				{
					return eccInfo.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException e)
				{
					throw new IllegalStateException("Unable to create KDF material: " + e);
				}
			}
		}

		private static KeyMaterialGenerator ecc_cms_Generator = new RFC5753KeyMaterialGenerator();
	}

}