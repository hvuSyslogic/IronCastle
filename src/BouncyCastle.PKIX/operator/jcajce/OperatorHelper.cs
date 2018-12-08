using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.bsi;
using org.bouncycastle.asn1.eac;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.kisa;

using System;

namespace org.bouncycastle.@operator.jcajce
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using BSIObjectIdentifiers = org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSException = org.bouncycastle.cms.CMSException;
	using AlgorithmParametersUtils = org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using MessageDigestUtils = org.bouncycastle.jcajce.util.MessageDigestUtils;
	using Integers = org.bouncycastle.util.Integers;

	public class OperatorHelper
	{
		private static readonly Map oids = new HashMap();
		private static readonly Map asymmetricWrapperAlgNames = new HashMap();
		private static readonly Map symmetricWrapperAlgNames = new HashMap();
		private static readonly Map symmetricKeyAlgNames = new HashMap();
		private static readonly Map symmetricWrapperKeySizes = new HashMap();

		static OperatorHelper()
		{
			//
			// reverse mappings
			//
			oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, "SHA224WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, "SHA256WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, "SHA384WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, "SHA512WITHRSA");
			oids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
			oids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
			oids.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
			oids.put(RosstandartObjectIdentifiers_Fields.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
			oids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
			oids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
			oids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
			oids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
			oids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
			oids.put(BSIObjectIdentifiers_Fields.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
			oids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
			oids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
			oids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
			oids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
			oids.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");

			oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
			oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
			oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, "SHA1WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224, "SHA224WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256, "SHA256WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384, "SHA384WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512, "SHA512WITHECDSA");
			oids.put(OIWObjectIdentifiers_Fields.sha1WithRSA, "SHA1WITHRSA");
			oids.put(OIWObjectIdentifiers_Fields.dsaWithSHA1, "SHA1WITHDSA");
			oids.put(NISTObjectIdentifiers_Fields.dsa_with_sha224, "SHA224WITHDSA");
			oids.put(NISTObjectIdentifiers_Fields.dsa_with_sha256, "SHA256WITHDSA");

			oids.put(OIWObjectIdentifiers_Fields.idSHA1, "SHA1");
			oids.put(NISTObjectIdentifiers_Fields.id_sha224, "SHA224");
			oids.put(NISTObjectIdentifiers_Fields.id_sha256, "SHA256");
			oids.put(NISTObjectIdentifiers_Fields.id_sha384, "SHA384");
			oids.put(NISTObjectIdentifiers_Fields.id_sha512, "SHA512");
			oids.put(TeleTrusTObjectIdentifiers_Fields.ripemd128, "RIPEMD128");
			oids.put(TeleTrusTObjectIdentifiers_Fields.ripemd160, "RIPEMD160");
			oids.put(TeleTrusTObjectIdentifiers_Fields.ripemd256, "RIPEMD256");

			asymmetricWrapperAlgNames.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA/ECB/PKCS1Padding");

			asymmetricWrapperAlgNames.put(CryptoProObjectIdentifiers_Fields.gostR3410_2001, "ECGOST3410");

			symmetricWrapperAlgNames.put(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap, "DESEDEWrap");
			symmetricWrapperAlgNames.put(PKCSObjectIdentifiers_Fields.id_alg_CMSRC2wrap, "RC2Wrap");
			symmetricWrapperAlgNames.put(NISTObjectIdentifiers_Fields.id_aes128_wrap, "AESWrap");
			symmetricWrapperAlgNames.put(NISTObjectIdentifiers_Fields.id_aes192_wrap, "AESWrap");
			symmetricWrapperAlgNames.put(NISTObjectIdentifiers_Fields.id_aes256_wrap, "AESWrap");
			symmetricWrapperAlgNames.put(NTTObjectIdentifiers_Fields.id_camellia128_wrap, "CamelliaWrap");
			symmetricWrapperAlgNames.put(NTTObjectIdentifiers_Fields.id_camellia192_wrap, "CamelliaWrap");
			symmetricWrapperAlgNames.put(NTTObjectIdentifiers_Fields.id_camellia256_wrap, "CamelliaWrap");
			symmetricWrapperAlgNames.put(KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap, "SEEDWrap");
			symmetricWrapperAlgNames.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, "DESede");

			symmetricWrapperKeySizes.put(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap, Integers.valueOf(192));
			symmetricWrapperKeySizes.put(NISTObjectIdentifiers_Fields.id_aes128_wrap, Integers.valueOf(128));
			symmetricWrapperKeySizes.put(NISTObjectIdentifiers_Fields.id_aes192_wrap, Integers.valueOf(192));
			symmetricWrapperKeySizes.put(NISTObjectIdentifiers_Fields.id_aes256_wrap, Integers.valueOf(256));
			symmetricWrapperKeySizes.put(NTTObjectIdentifiers_Fields.id_camellia128_wrap, Integers.valueOf(128));
			symmetricWrapperKeySizes.put(NTTObjectIdentifiers_Fields.id_camellia192_wrap, Integers.valueOf(192));
			symmetricWrapperKeySizes.put(NTTObjectIdentifiers_Fields.id_camellia256_wrap, Integers.valueOf(256));
			symmetricWrapperKeySizes.put(KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap, Integers.valueOf(128));
			symmetricWrapperKeySizes.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, Integers.valueOf(192));

			symmetricKeyAlgNames.put(NISTObjectIdentifiers_Fields.aes, "AES");
			symmetricKeyAlgNames.put(NISTObjectIdentifiers_Fields.id_aes128_CBC, "AES");
			symmetricKeyAlgNames.put(NISTObjectIdentifiers_Fields.id_aes192_CBC, "AES");
			symmetricKeyAlgNames.put(NISTObjectIdentifiers_Fields.id_aes256_CBC, "AES");
			symmetricKeyAlgNames.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, "DESede");
			symmetricKeyAlgNames.put(PKCSObjectIdentifiers_Fields.RC2_CBC, "RC2");
		}

		private JcaJceHelper helper;

		public OperatorHelper(JcaJceHelper helper)
		{
			this.helper = helper;
		}

		public virtual string getWrappingAlgorithmName(ASN1ObjectIdentifier algOid)
		{
			return (string)symmetricWrapperAlgNames.get(algOid);
		}

		public virtual int getKeySizeInBits(ASN1ObjectIdentifier algOid)
		{
			return ((int?)symmetricWrapperKeySizes.get(algOid)).Value;
		}

		public virtual KeyPairGenerator createKeyPairGenerator(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string agreementName = null; //(String)BASE_CIPHER_NAMES.get(algorithm);

				if (!string.ReferenceEquals(agreementName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyPairGenerator(agreementName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createKeyPairGenerator(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create key agreement: " + e.Message, e);
			}
		}

		public virtual Cipher createCipher(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				return helper.createCipher(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual KeyAgreement createKeyAgreement(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string agreementName = null; //(String)BASE_CIPHER_NAMES.get(algorithm);

				if (!string.ReferenceEquals(agreementName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyAgreement(agreementName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createKeyAgreement(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException("cannot create key agreement: " + e.Message, e);
			}
		}

		public virtual Cipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm, Map extraAlgNames)
		{
			try
			{
				string cipherName = null;

				if (!extraAlgNames.isEmpty())
				{
					cipherName = (string)extraAlgNames.get(algorithm);
				}

				if (string.ReferenceEquals(cipherName, null))
				{
					cipherName = (string)asymmetricWrapperAlgNames.get(algorithm);
				}

				if (!string.ReferenceEquals(cipherName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createCipher(cipherName);
					}
					catch (NoSuchAlgorithmException)
					{
						// try alternate for RSA
						if (cipherName.Equals("RSA/ECB/PKCS1Padding"))
						{
							try
							{
								return helper.createCipher("RSA/NONE/PKCS1Padding");
							}
							catch (NoSuchAlgorithmException)
							{
								// Ignore
							}
						}
						// Ignore
					}
				}

				return helper.createCipher(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual Cipher createSymmetricWrapper(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string cipherName = (string)symmetricWrapperAlgNames.get(algorithm);

				if (!string.ReferenceEquals(cipherName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createCipher(cipherName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createCipher(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual AlgorithmParameters createAlgorithmParameters(AlgorithmIdentifier cipherAlgId)
		{
			AlgorithmParameters parameters;

			if (cipherAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.rsaEncryption))
			{
				return null;
			}

			try
			{
				parameters = helper.createAlgorithmParameters(cipherAlgId.getAlgorithm().getId());
			}
			catch (NoSuchAlgorithmException)
			{
				return null; // There's a good chance there aren't any!
			}
			catch (NoSuchProviderException e)
			{
				throw new OperatorCreationException("cannot create algorithm parameters: " + e.Message, e);
			}

			try
			{
				parameters.init(cipherAlgId.getParameters().toASN1Primitive().getEncoded());
			}
			catch (IOException e)
			{
				throw new OperatorCreationException("cannot initialise algorithm parameters: " + e.Message, e);
			}

			return parameters;
		}

		public virtual MessageDigest createDigest(AlgorithmIdentifier digAlgId)
		{
			MessageDigest dig;

			try
			{
				dig = helper.createDigest(MessageDigestUtils.getDigestName(digAlgId.getAlgorithm()));
			}
			catch (NoSuchAlgorithmException e)
			{
				//
				// try an alternate
				//
				if (oids.get(digAlgId.getAlgorithm()) != null)
				{
					string digestAlgorithm = (string)oids.get(digAlgId.getAlgorithm());

					dig = helper.createDigest(digestAlgorithm);
				}
				else
				{
					throw e;
				}
			}

			return dig;
		}

		public virtual Signature createSignature(AlgorithmIdentifier sigAlgId)
		{
			Signature sig;

			try
			{
				sig = helper.createSignature(getSignatureName(sigAlgId));
			}
			catch (NoSuchAlgorithmException e)
			{
				//
				// try an alternate
				//
				if (oids.get(sigAlgId.getAlgorithm()) != null)
				{
					string signatureAlgorithm = (string)oids.get(sigAlgId.getAlgorithm());

					sig = helper.createSignature(signatureAlgorithm);
				}
				else
				{
					throw e;
				}
			}

			if (sigAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
			{
				ASN1Sequence seq = ASN1Sequence.getInstance(sigAlgId.getParameters());

				if (notDefaultPSSParams(seq))
				{
					try
					{
						AlgorithmParameters algParams = helper.createAlgorithmParameters("PSS");

						algParams.init(seq.getEncoded());

						sig.setParameter(algParams.getParameterSpec(typeof(PSSParameterSpec)));
					}
					catch (IOException e)
					{
						throw new GeneralSecurityException("unable to process PSS parameters: " + e.Message);
					}
				}
			}

			return sig;
		}

		public virtual Signature createRawSignature(AlgorithmIdentifier algorithm)
		{
			Signature sig;

			try
			{
				string algName = getSignatureName(algorithm);

				algName = "NONE" + algName.Substring(algName.IndexOf("WITH", StringComparison.Ordinal));

				sig = helper.createSignature(algName);

				// RFC 4056
				// When the id-RSASSA-PSS algorithm identifier is used for a signature,
				// the AlgorithmIdentifier parameters field MUST contain RSASSA-PSS-params.
				if (algorithm.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
				{
					AlgorithmParameters @params = helper.createAlgorithmParameters(algName);

					AlgorithmParametersUtils.loadParameters(@params, algorithm.getParameters());

					PSSParameterSpec spec = (PSSParameterSpec)@params.getParameterSpec(typeof(PSSParameterSpec));
					sig.setParameter(spec);
				}
			}
			catch (Exception)
			{
				return null;
			}

			return sig;
		}

		private static string getSignatureName(AlgorithmIdentifier sigAlgId)
		{
			ASN1Encodable @params = sigAlgId.getParameters();

			if (@params != null && !DERNull.INSTANCE.Equals(@params))
			{
				if (sigAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
				{
					RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(@params);
					return getDigestName(rsaParams.getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
				}
			}

			if (oids.containsKey(sigAlgId.getAlgorithm()))
			{
				return (string)oids.get(sigAlgId.getAlgorithm());
			}

			return sigAlgId.getAlgorithm().getId();
		}

		// we need to remove the - to create a correct signature name
		private static string getDigestName(ASN1ObjectIdentifier oid)
		{
			string name = MessageDigestUtils.getDigestName(oid);

			int dIndex = name.IndexOf('-');
			if (dIndex > 0 && !name.StartsWith("SHA3", StringComparison.Ordinal))
			{
				return name.Substring(0, dIndex) + name.Substring(dIndex + 1);
			}

			return name;
		}

		public virtual X509Certificate convertCertificate(X509CertificateHolder certHolder)
		{
			try
			{
				CertificateFactory certFact = helper.createCertificateFactory("X.509");

				return (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
			}
			catch (IOException e)
			{
				throw new OpCertificateException("cannot get encoded form of certificate: " + e.Message, e);
			}
			catch (NoSuchProviderException e)
			{
				throw new OpCertificateException("cannot find factory provider: " + e.Message, e);
			}
		}

		public virtual PublicKey convertPublicKey(SubjectPublicKeyInfo publicKeyInfo)
		{
			try
			{
				KeyFactory keyFact = helper.createKeyFactory(publicKeyInfo.getAlgorithm().getAlgorithm().getId());

				return keyFact.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
			}
			catch (IOException e)
			{
				throw new OperatorCreationException("cannot get encoded form of key: " + e.Message, e);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new OperatorCreationException("cannot create key factory: " + e.Message, e);
			}
			catch (NoSuchProviderException e)
			{
				throw new OperatorCreationException("cannot find factory provider: " + e.Message, e);
			}
			catch (InvalidKeySpecException e)
			{
				throw new OperatorCreationException("cannot create key factory: " + e.Message, e);
			}
		}

		// TODO: put somewhere public so cause easily accessed
		public class OpCertificateException : CertificateException
		{
			internal Exception cause;

			public OpCertificateException(string msg, Exception cause) : base(msg)
			{

				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}

		public virtual string getKeyAlgorithmName(ASN1ObjectIdentifier oid)
		{

			string name = (string)symmetricKeyAlgNames.get(oid);

			if (!string.ReferenceEquals(name, null))
			{
				return name;
			}

			return oid.getId();
		}

		// for our purposes default includes varient digest with salt the same size as digest
		private bool notDefaultPSSParams(ASN1Sequence seq)
		{
			if (seq == null || seq.size() == 0)
			{
				return false;
			}

			RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(seq);

			if (!pssParams.getMaskGenAlgorithm().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_mgf1))
			{
				return true;
			}

			// same digest for sig and MGF1
			if (!pssParams.getHashAlgorithm().Equals(AlgorithmIdentifier.getInstance(pssParams.getMaskGenAlgorithm().getParameters())))
			{
				return true;
			}

			MessageDigest digest = createDigest(pssParams.getHashAlgorithm());

			return pssParams.getSaltLength().intValue() != digest.getDigestLength();
		}
	}

}