using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;

namespace org.bouncycastle.jcajce.provider.asymmetric
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using KeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	public class RSA
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".rsa.";

		private static readonly Map<string, string> generalRsaAttributes = new HashMap<string, string>();

		static RSA()
		{
			generalRsaAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.RSAPublicKey|javax.crypto.interfaces.RSAPrivateKey");
			generalRsaAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
		}

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.OAEP", PREFIX + "AlgorithmParametersSpi$OAEP");
				provider.addAlgorithm("AlgorithmParameters.PSS", PREFIX + "AlgorithmParametersSpi$PSS");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RSAPSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RSASSA-PSS", "PSS");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224withRSA/PSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256withRSA/PSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384withRSA/PSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512withRSA/PSS", "PSS");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-224WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-256WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-384WITHRSAANDMGF1", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-512WITHRSAANDMGF1", "PSS");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RAWRSAPSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAPSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSASSA-PSS", "PSS");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAANDMGF1", "PSS");

				provider.addAttributes("Cipher.RSA", generalRsaAttributes);
				provider.addAlgorithm("Cipher.RSA", PREFIX + "CipherSpi$NoPadding");
				provider.addAlgorithm("Cipher.RSA/RAW", PREFIX + "CipherSpi$NoPadding");
				provider.addAlgorithm("Cipher.RSA/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
				provider.addAlgorithm("Cipher", PKCSObjectIdentifiers_Fields.rsaEncryption, PREFIX + "CipherSpi$PKCS1v1_5Padding");
				provider.addAlgorithm("Cipher", X509ObjectIdentifiers_Fields.id_ea_rsa, PREFIX + "CipherSpi$PKCS1v1_5Padding");
				provider.addAlgorithm("Cipher.RSA/1", PREFIX + "CipherSpi$PKCS1v1_5Padding_PrivateOnly");
				provider.addAlgorithm("Cipher.RSA/2", PREFIX + "CipherSpi$PKCS1v1_5Padding_PublicOnly");
				provider.addAlgorithm("Cipher.RSA/OAEP", PREFIX + "CipherSpi$OAEPPadding");
				provider.addAlgorithm("Cipher", PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, PREFIX + "CipherSpi$OAEPPadding");
				provider.addAlgorithm("Cipher.RSA/ISO9796-1", PREFIX + "CipherSpi$ISO9796d1Padding");

				provider.addAlgorithm("Alg.Alias.Cipher.RSA//RAW", "RSA");
				provider.addAlgorithm("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
				provider.addAlgorithm("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
				provider.addAlgorithm("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
				provider.addAlgorithm("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");

				provider.addAlgorithm("KeyFactory.RSA", PREFIX + "KeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.RSA", PREFIX + "KeyPairGeneratorSpi");

				AsymmetricKeyInfoConverter keyFact = new KeyFactorySpi();

				registerOid(provider, PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA", keyFact);
				registerOid(provider, X509ObjectIdentifiers_Fields.id_ea_rsa, "RSA", keyFact);
				registerOid(provider, PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, "RSA", keyFact);
				registerOid(provider, PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, "RSA", keyFact);

				registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
				registerOidAlgorithmParameters(provider, X509ObjectIdentifiers_Fields.id_ea_rsa, "RSA");
				registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, "OAEP");
				registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, "PSS");

				provider.addAlgorithm("Signature.RSASSA-PSS", PREFIX + "PSSSignatureSpi$PSSwithRSA");
				provider.addAlgorithm("Signature." + PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, PREFIX + "PSSSignatureSpi$PSSwithRSA");
				provider.addAlgorithm("Signature.OID." + PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, PREFIX + "PSSSignatureSpi$PSSwithRSA");

				provider.addAlgorithm("Signature.RSA", PREFIX + "DigestSignatureSpi$noneRSA");
				provider.addAlgorithm("Signature.RAWRSASSA-PSS", PREFIX + "PSSSignatureSpi$nonePSS");

				provider.addAlgorithm("Alg.Alias.Signature.RAWRSA", "RSA");
				provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSA", "RSA");
				provider.addAlgorithm("Alg.Alias.Signature.RAWRSAPSS", "RAWRSASSA-PSS");
				provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAPSS", "RAWRSASSA-PSS");
				provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSASSA-PSS", "RAWRSASSA-PSS");
				provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAANDMGF1", "RAWRSASSA-PSS");
				provider.addAlgorithm("Alg.Alias.Signature.RSAPSS", "RSASSA-PSS");

				addPSSSignature(provider, "SHA224", PREFIX + "PSSSignatureSpi$SHA224withRSA");
				addPSSSignature(provider, "SHA256", PREFIX + "PSSSignatureSpi$SHA256withRSA");
				addPSSSignature(provider, "SHA384", PREFIX + "PSSSignatureSpi$SHA384withRSA");
				addPSSSignature(provider, "SHA512", PREFIX + "PSSSignatureSpi$SHA512withRSA");
				addPSSSignature(provider, "SHA512(224)", PREFIX + "PSSSignatureSpi$SHA512_224withRSA");
				addPSSSignature(provider, "SHA512(256)", PREFIX + "PSSSignatureSpi$SHA512_256withRSA");

				addPSSSignature(provider, "SHA3-224", PREFIX + "PSSSignatureSpi$SHA3_224withRSA");
				addPSSSignature(provider, "SHA3-256", PREFIX + "PSSSignatureSpi$SHA3_256withRSA");
				addPSSSignature(provider, "SHA3-384", PREFIX + "PSSSignatureSpi$SHA3_384withRSA");
				addPSSSignature(provider, "SHA3-512", PREFIX + "PSSSignatureSpi$SHA3_512withRSA");

				if (provider.hasAlgorithm("MessageDigest", "MD2"))
				{
					addDigestSignature(provider, "MD2", PREFIX + "DigestSignatureSpi$MD2", PKCSObjectIdentifiers_Fields.md2WithRSAEncryption);
				}

				if (provider.hasAlgorithm("MessageDigest", "MD4"))
				{
					addDigestSignature(provider, "MD4", PREFIX + "DigestSignatureSpi$MD4", PKCSObjectIdentifiers_Fields.md4WithRSAEncryption);
				}

				if (provider.hasAlgorithm("MessageDigest", "MD5"))
				{
					addDigestSignature(provider, "MD5", PREFIX + "DigestSignatureSpi$MD5", PKCSObjectIdentifiers_Fields.md5WithRSAEncryption);
					addISO9796Signature(provider, "MD5", PREFIX + "ISOSignatureSpi$MD5WithRSAEncryption");
				}

				if (provider.hasAlgorithm("MessageDigest", "SHA1"))
				{
					provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1withRSA/PSS", "PSS");
					provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1WITHRSAANDMGF1", "PSS");

					addPSSSignature(provider, "SHA1", PREFIX + "PSSSignatureSpi$SHA1withRSA");
					addDigestSignature(provider, "SHA1", PREFIX + "DigestSignatureSpi$SHA1", PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
					addISO9796Signature(provider, "SHA1", PREFIX + "ISOSignatureSpi$SHA1WithRSAEncryption");

					provider.addAlgorithm("Alg.Alias.Signature." + OIWObjectIdentifiers_Fields.sha1WithRSA, "SHA1WITHRSA");
					provider.addAlgorithm("Alg.Alias.Signature.OID." + OIWObjectIdentifiers_Fields.sha1WithRSA, "SHA1WITHRSA");

					addX931Signature(provider, "SHA1", PREFIX + "X931SignatureSpi$SHA1WithRSAEncryption");
				}

				addDigestSignature(provider, "SHA224", PREFIX + "DigestSignatureSpi$SHA224", PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption);
				addDigestSignature(provider, "SHA256", PREFIX + "DigestSignatureSpi$SHA256", PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption);
				addDigestSignature(provider, "SHA384", PREFIX + "DigestSignatureSpi$SHA384", PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption);
				addDigestSignature(provider, "SHA512", PREFIX + "DigestSignatureSpi$SHA512", PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption);
				addDigestSignature(provider, "SHA512(224)", PREFIX + "DigestSignatureSpi$SHA512_224", PKCSObjectIdentifiers_Fields.sha512_224WithRSAEncryption);
				addDigestSignature(provider, "SHA512(256)", PREFIX + "DigestSignatureSpi$SHA512_256", PKCSObjectIdentifiers_Fields.sha512_256WithRSAEncryption);

				addDigestSignature(provider, "SHA3-224", PREFIX + "DigestSignatureSpi$SHA3_224", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_224);
				addDigestSignature(provider, "SHA3-256", PREFIX + "DigestSignatureSpi$SHA3_256", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_256);
				addDigestSignature(provider, "SHA3-384", PREFIX + "DigestSignatureSpi$SHA3_384", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_384);
				addDigestSignature(provider, "SHA3-512", PREFIX + "DigestSignatureSpi$SHA3_512", NISTObjectIdentifiers_Fields.id_rsassa_pkcs1_v1_5_with_sha3_512);

				addISO9796Signature(provider, "SHA224", PREFIX + "ISOSignatureSpi$SHA224WithRSAEncryption");
				addISO9796Signature(provider, "SHA256", PREFIX + "ISOSignatureSpi$SHA256WithRSAEncryption");
				addISO9796Signature(provider, "SHA384", PREFIX + "ISOSignatureSpi$SHA384WithRSAEncryption");
				addISO9796Signature(provider, "SHA512", PREFIX + "ISOSignatureSpi$SHA512WithRSAEncryption");
				addISO9796Signature(provider, "SHA512(224)", PREFIX + "ISOSignatureSpi$SHA512_224WithRSAEncryption");
				addISO9796Signature(provider, "SHA512(256)", PREFIX + "ISOSignatureSpi$SHA512_256WithRSAEncryption");

				addX931Signature(provider, "SHA224", PREFIX + "X931SignatureSpi$SHA224WithRSAEncryption");
				addX931Signature(provider, "SHA256", PREFIX + "X931SignatureSpi$SHA256WithRSAEncryption");
				addX931Signature(provider, "SHA384", PREFIX + "X931SignatureSpi$SHA384WithRSAEncryption");
				addX931Signature(provider, "SHA512", PREFIX + "X931SignatureSpi$SHA512WithRSAEncryption");
				addX931Signature(provider, "SHA512(224)", PREFIX + "X931SignatureSpi$SHA512_224WithRSAEncryption");
				addX931Signature(provider, "SHA512(256)", PREFIX + "X931SignatureSpi$SHA512_256WithRSAEncryption");

				if (provider.hasAlgorithm("MessageDigest", "RIPEMD128"))
				{
					addDigestSignature(provider, "RIPEMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
					addDigestSignature(provider, "RMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", null);

					addX931Signature(provider, "RMD128", PREFIX + "X931SignatureSpi$RIPEMD128WithRSAEncryption");
					addX931Signature(provider, "RIPEMD128", PREFIX + "X931SignatureSpi$RIPEMD128WithRSAEncryption");
				}

				if (provider.hasAlgorithm("MessageDigest", "RIPEMD160"))
				{
					addDigestSignature(provider, "RIPEMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
					addDigestSignature(provider, "RMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", null);
					provider.addAlgorithm("Alg.Alias.Signature.RIPEMD160WithRSA/ISO9796-2", "RIPEMD160withRSA/ISO9796-2");
					provider.addAlgorithm("Signature.RIPEMD160withRSA/ISO9796-2", PREFIX + "ISOSignatureSpi$RIPEMD160WithRSAEncryption");

					addX931Signature(provider, "RMD160", PREFIX + "X931SignatureSpi$RIPEMD160WithRSAEncryption");
					addX931Signature(provider, "RIPEMD160", PREFIX + "X931SignatureSpi$RIPEMD160WithRSAEncryption");
				}

				if (provider.hasAlgorithm("MessageDigest", "RIPEMD256"))
				{
					addDigestSignature(provider, "RIPEMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
					addDigestSignature(provider, "RMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", null);
				}

				if (provider.hasAlgorithm("MessageDigest", "WHIRLPOOL"))
				{
					addISO9796Signature(provider, "Whirlpool", PREFIX + "ISOSignatureSpi$WhirlpoolWithRSAEncryption");
					addISO9796Signature(provider, "WHIRLPOOL", PREFIX + "ISOSignatureSpi$WhirlpoolWithRSAEncryption");
					addX931Signature(provider, "Whirlpool", PREFIX + "X931SignatureSpi$WhirlpoolWithRSAEncryption");
					addX931Signature(provider, "WHIRLPOOL", PREFIX + "X931SignatureSpi$WhirlpoolWithRSAEncryption");
				}
			}

			public virtual void addDigestSignature(ConfigurableProvider provider, string digest, string className, ASN1ObjectIdentifier oid)
			{
				string mainName = digest + "WITHRSA";
				string jdk11Variation1 = digest + "withRSA";
				string jdk11Variation2 = digest + "WithRSA";
				string alias = digest + "/" + "RSA";
				string longName = digest + "WITHRSAENCRYPTION";
				string longJdk11Variation1 = digest + "withRSAEncryption";
				string longJdk11Variation2 = digest + "WithRSAEncryption";

				provider.addAlgorithm("Signature." + mainName, className);
				provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
				provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
				provider.addAlgorithm("Alg.Alias.Signature." + longName, mainName);
				provider.addAlgorithm("Alg.Alias.Signature." + longJdk11Variation1, mainName);
				provider.addAlgorithm("Alg.Alias.Signature." + longJdk11Variation2, mainName);
				provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);

				if (oid != null)
				{
					provider.addAlgorithm("Alg.Alias.Signature." + oid, mainName);
					provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, mainName);
				}
			}

			public virtual void addISO9796Signature(ConfigurableProvider provider, string digest, string className)
			{
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/ISO9796-2", digest + "WITHRSA/ISO9796-2");
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/ISO9796-2", digest + "WITHRSA/ISO9796-2");
				provider.addAlgorithm("Signature." + digest + "WITHRSA/ISO9796-2", className);
			}

			public virtual void addPSSSignature(ConfigurableProvider provider, string digest, string className)
			{
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/PSS", digest + "WITHRSAANDMGF1");
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/PSS", digest + "WITHRSAANDMGF1");
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSAandMGF1", digest + "WITHRSAANDMGF1");
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSAAndMGF1", digest + "WITHRSAANDMGF1");
				provider.addAlgorithm("Signature." + digest + "WITHRSAANDMGF1", className);
			}

			public virtual void addX931Signature(ConfigurableProvider provider, string digest, string className)
			{
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/X9.31", digest + "WITHRSA/X9.31");
				provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/X9.31", digest + "WITHRSA/X9.31");
				provider.addAlgorithm("Signature." + digest + "WITHRSA/X9.31", className);
			}
		}
	}

}