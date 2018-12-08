using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.kisa;
using org.bouncycastle.asn1.ntt;

using System;

namespace org.bouncycastle.@operator.jcajce
{


	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JceSymmetricKeyWrapper : SymmetricKeyWrapper
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private SecureRandom random;
		private SecretKey wrappingKey;

		public JceSymmetricKeyWrapper(SecretKey wrappingKey) : base(determineKeyEncAlg(wrappingKey))
		{

			this.wrappingKey = wrappingKey;
		}

		public virtual JceSymmetricKeyWrapper setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceSymmetricKeyWrapper setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual JceSymmetricKeyWrapper setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override byte[] generateWrappedKey(GenericKey encryptionKey)
		{
			Key contentEncryptionKeySpec = OperatorUtils.getJceKey(encryptionKey);

			Cipher keyEncryptionCipher = helper.createSymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm());

			try
			{
				keyEncryptionCipher.init(Cipher.WRAP_MODE, wrappingKey, random);

				return keyEncryptionCipher.wrap(contentEncryptionKeySpec);
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorException("cannot wrap key: " + e.Message, e);
			}
		}

		private static AlgorithmIdentifier determineKeyEncAlg(SecretKey key)
		{
			return determineKeyEncAlg(key.getAlgorithm(), key.getEncoded().length * 8);
		}

		internal static AlgorithmIdentifier determineKeyEncAlg(string algorithm, int keySizeInBits)
		{
			if (algorithm.StartsWith("DES", StringComparison.Ordinal) || algorithm.StartsWith("TripleDES", StringComparison.Ordinal))
			{
				return new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap, DERNull.INSTANCE);
			}
			else if (algorithm.StartsWith("RC2", StringComparison.Ordinal))
			{
				return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.7"), new ASN1Integer(58));
			}
			else if (algorithm.StartsWith("AES", StringComparison.Ordinal))
			{
				ASN1ObjectIdentifier wrapOid;

				if (keySizeInBits == 128)
				{
					wrapOid = NISTObjectIdentifiers_Fields.id_aes128_wrap;
				}
				else if (keySizeInBits == 192)
				{
					wrapOid = NISTObjectIdentifiers_Fields.id_aes192_wrap;
				}
				else if (keySizeInBits == 256)
				{
					wrapOid = NISTObjectIdentifiers_Fields.id_aes256_wrap;
				}
				else
				{
					throw new IllegalArgumentException("illegal keysize in AES");
				}

				return new AlgorithmIdentifier(wrapOid); // parameters absent
			}
			else if (algorithm.StartsWith("SEED", StringComparison.Ordinal))
			{
				// parameters absent
				return new AlgorithmIdentifier(KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap);
			}
			else if (algorithm.StartsWith("Camellia", StringComparison.Ordinal))
			{
				ASN1ObjectIdentifier wrapOid;

				if (keySizeInBits == 128)
				{
					wrapOid = NTTObjectIdentifiers_Fields.id_camellia128_wrap;
				}
				else if (keySizeInBits == 192)
				{
					wrapOid = NTTObjectIdentifiers_Fields.id_camellia192_wrap;
				}
				else if (keySizeInBits == 256)
				{
					wrapOid = NTTObjectIdentifiers_Fields.id_camellia256_wrap;
				}
				else
				{
					throw new IllegalArgumentException("illegal keysize in Camellia");
				}

				return new AlgorithmIdentifier(wrapOid); // parameters must be
														 // absent
			}
			else
			{
				throw new IllegalArgumentException("unknown algorithm");
			}
		}
	}

}