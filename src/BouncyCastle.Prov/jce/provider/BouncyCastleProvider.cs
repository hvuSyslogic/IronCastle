using org.bouncycastle.pqc.asn1;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using ClassUtil = org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceCCA2KeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi;
	using McElieceKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi;
	using NHKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.newhope.NHKeyFactorySpi;
	using QTESLAKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;
	using RainbowKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi;
	using Sphincs256KeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;
	using XMSSKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
	using XMSSMTKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;

	/// <summary>
	/// To add the provider at runtime use:
	/// <pre>
	/// import java.security.Security;
	/// import org.bouncycastle.jce.provider.BouncyCastleProvider;
	/// 
	/// Security.addProvider(new BouncyCastleProvider());
	/// </pre>
	/// The provider can also be configured as part of your environment via
	/// static registration by adding an entry to the java.security properties
	/// file (found in $JAVA_HOME/jre/lib/security/java.security, where
	/// $JAVA_HOME is the location of your JDK/JRE distribution). You'll find
	/// detailed instructions in the file but basically it comes down to adding
	/// a line:
	/// <pre>
	/// <code>
	///    security.provider.&lt;n&gt;=org.bouncycastle.jce.provider.BouncyCastleProvider
	/// </code>
	/// </pre>
	/// Where &lt;n&gt; is the preference you want the provider at (1 being the
	/// most preferred).
	/// <para>Note: JCE algorithm names should be upper-case only so the case insensitive
	/// test for getInstance works.
	/// </para>
	/// </summary>
	public sealed class BouncyCastleProvider : Provider, ConfigurableProvider
	{
		private static string info = "BouncyCastle Security Provider v1.61b";

		public const string PROVIDER_NAME = "BC";

		public static readonly ProviderConfiguration CONFIGURATION = new BouncyCastleProviderConfiguration();

		private static readonly Map keyInfoConverters = new HashMap();

		/*
		 * Configurable symmetric ciphers
		 */
		private const string SYMMETRIC_PACKAGE = "org.bouncycastle.jcajce.provider.symmetric.";

		private static readonly string[] SYMMETRIC_GENERIC = new string[] {"PBEPBKDF1", "PBEPBKDF2", "PBEPKCS12", "TLSKDF", "SCRYPT"};

		private static readonly string[] SYMMETRIC_MACS = new string[] {"SipHash", "Poly1305"};

		private static readonly string[] SYMMETRIC_CIPHERS = new string[] {"AES", "ARC4", "ARIA", "Blowfish", "Camellia", "CAST5", "CAST6", "ChaCha", "DES", "DESede", "GOST28147", "Grainv1", "Grain128", "HC128", "HC256", "IDEA", "Noekeon", "RC2", "RC5", "RC6", "Rijndael", "Salsa20", "SEED", "Serpent", "Shacal2", "Skipjack", "SM4", "TEA", "Twofish", "Threefish", "VMPC", "VMPCKSA3", "XTEA", "XSalsa20", "OpenSSLPBKDF", "DSTU7624", "GOST3412_2015"};

		 /*
		 * Configurable asymmetric ciphers
		 */
		private const string ASYMMETRIC_PACKAGE = "org.bouncycastle.jcajce.provider.asymmetric.";

		// this one is required for GNU class path - it needs to be loaded first as the
		// later ones configure it.
		private static readonly string[] ASYMMETRIC_GENERIC = new string[] {"X509", "IES"};

		private static readonly string[] ASYMMETRIC_CIPHERS = new string[] {"DSA", "DH", "EC", "RSA", "GOST", "ECGOST", "ElGamal", "DSTU4145", "GM", "EdEC"};

		/*
		 * Configurable digests
		 */
		private const string DIGEST_PACKAGE = "org.bouncycastle.jcajce.provider.digest.";
		private static readonly string[] DIGESTS = new string[] {"GOST3411", "Keccak", "MD2", "MD4", "MD5", "SHA1", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3", "Skein", "SM3", "Tiger", "Whirlpool", "Blake2b", "Blake2s", "DSTU7564"};

		/*
		 * Configurable keystores
		 */
		private const string KEYSTORE_PACKAGE = "org.bouncycastle.jcajce.provider.keystore.";
		private static readonly string[] KEYSTORES = new string[] {"BC", "BCFKS", "PKCS12"};

		/*
		 * Configurable secure random
		 */
		private const string SECURE_RANDOM_PACKAGE = "org.bouncycastle.jcajce.provider.drbg.";
		private static readonly string[] SECURE_RANDOMS = new string[] {"DRBG"};

		/// <summary>
		/// Construct a new provider.  This should only be required when
		/// using runtime registration of the provider using the
		/// <code>Security.addProvider()</code> mechanism.
		/// </summary>
		public BouncyCastleProvider() : base(PROVIDER_NAME, 1.6050, info)
		{

			AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(this));
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private readonly BouncyCastleProvider outerInstance;

			public PrivilegedActionAnonymousInnerClass(BouncyCastleProvider outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public object run()
			{
				outerInstance.setup();
				return null;
			}
		}

		private void setup()
		{
			loadAlgorithms(DIGEST_PACKAGE, DIGESTS);

			loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_GENERIC);

			loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_MACS);

			loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_CIPHERS);

			loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_GENERIC);

			loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_CIPHERS);

			loadAlgorithms(KEYSTORE_PACKAGE, KEYSTORES);

			loadAlgorithms(SECURE_RANDOM_PACKAGE, SECURE_RANDOMS);

			loadPQCKeys(); // so we can handle certificates containing them.
			//
			// X509Store
			//
			put("X509Store.CERTIFICATE/COLLECTION", "org.bouncycastle.jce.provider.X509StoreCertCollection");
			put("X509Store.ATTRIBUTECERTIFICATE/COLLECTION", "org.bouncycastle.jce.provider.X509StoreAttrCertCollection");
			put("X509Store.CRL/COLLECTION", "org.bouncycastle.jce.provider.X509StoreCRLCollection");
			put("X509Store.CERTIFICATEPAIR/COLLECTION", "org.bouncycastle.jce.provider.X509StoreCertPairCollection");

			put("X509Store.CERTIFICATE/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPCerts");
			put("X509Store.CRL/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPCRLs");
			put("X509Store.ATTRIBUTECERTIFICATE/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPAttrCerts");
			put("X509Store.CERTIFICATEPAIR/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPCertPairs");

			//
			// X509StreamParser
			//
			put("X509StreamParser.CERTIFICATE", "org.bouncycastle.jce.provider.X509CertParser");
			put("X509StreamParser.ATTRIBUTECERTIFICATE", "org.bouncycastle.jce.provider.X509AttrCertParser");
			put("X509StreamParser.CRL", "org.bouncycastle.jce.provider.X509CRLParser");
			put("X509StreamParser.CERTIFICATEPAIR", "org.bouncycastle.jce.provider.X509CertPairParser");

			//
			// cipher engines
			//
			put("Cipher.BROKENPBEWITHMD5ANDDES", "org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithMD5AndDES");

			put("Cipher.BROKENPBEWITHSHA1ANDDES", "org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES");


			put("Cipher.OLDPBEWITHSHAANDTWOFISH-CBC", "org.bouncycastle.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish");

			// Certification Path API
			put("CertPathValidator.RFC3281", "org.bouncycastle.jce.provider.PKIXAttrCertPathValidatorSpi");
			put("CertPathBuilder.RFC3281", "org.bouncycastle.jce.provider.PKIXAttrCertPathBuilderSpi");
			put("CertPathValidator.RFC3280", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi");
			put("CertPathBuilder.RFC3280", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi");
			put("CertPathValidator.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi");
			put("CertPathBuilder.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi");
			put("CertStore.Collection", "org.bouncycastle.jce.provider.CertStoreCollectionSpi");
			put("CertStore.LDAP", "org.bouncycastle.jce.provider.X509LDAPCertStoreSpi");
			put("CertStore.Multi", "org.bouncycastle.jce.provider.MultiCertStoreSpi");
			put("Alg.Alias.CertStore.X509LDAP", "LDAP");
		}

		private void loadAlgorithms(string packageName, string[] names)
		{
			for (int i = 0; i != names.Length; i++)
			{
				Class clazz = ClassUtil.loadClass(typeof(BouncyCastleProvider), packageName + names[i] + "$Mappings");

				if (clazz != null)
				{
					try
					{
						((AlgorithmProvider)clazz.newInstance()).configure(this);
					}
					catch (Exception e)
					{ // this should never ever happen!!
						throw new InternalError("cannot create instance of " + packageName + names[i] + "$Mappings : " + e);
					}
				}
			}
		}

		private void loadPQCKeys()
		{
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.sphincs256, new Sphincs256KeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.newHope, new NHKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.xmss, new XMSSKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.xmss_mt, new XMSSMTKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.mcEliece, new McElieceKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.mcElieceCca2, new McElieceCCA2KeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.rainbow, new RainbowKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.qTESLA_I, new QTESLAKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.qTESLA_III_size, new QTESLAKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.qTESLA_III_speed, new QTESLAKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.qTESLA_p_I, new QTESLAKeyFactorySpi());
			addKeyInfoConverter(PQCObjectIdentifiers_Fields.qTESLA_p_III, new QTESLAKeyFactorySpi());
		}

		public void setParameter(string parameterName, object parameter)
		{
			lock (CONFIGURATION)
			{
				((BouncyCastleProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
			}
		}

		public bool hasAlgorithm(string type, string name)
		{
			return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
		}

		public void addAlgorithm(string key, string value)
		{
			if (containsKey(key))
			{
				throw new IllegalStateException("duplicate provider key (" + key + ") found");
			}

			put(key, value);
		}

		public void addAlgorithm(string type, ASN1ObjectIdentifier oid, string className)
		{
			addAlgorithm(type + "." + oid, className);
			addAlgorithm(type + ".OID." + oid, className);
		}

		public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
		{
			lock (keyInfoConverters)
			{
				keyInfoConverters.put(oid, keyInfoConverter);
			}
		}

		public void addAttributes(string key, Map<string, string> attributeMap)
		{
			for (Iterator it = attributeMap.keySet().iterator(); it.hasNext();)
			{
				string attributeName = (string)it.next();
				string attributeKey = key + " " + attributeName;
				if (containsKey(attributeKey))
				{
					throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
				}

				put(attributeKey, attributeMap.get(attributeName));
			}
		}

		private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm)
		{
			lock (keyInfoConverters)
			{
				return (AsymmetricKeyInfoConverter)keyInfoConverters.get(algorithm);
			}
		}

		public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
		{
			AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());

			if (converter == null)
			{
				return null;
			}

			return converter.generatePublic(publicKeyInfo);
		}

		public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
		{
			AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

			if (converter == null)
			{
				return null;
			}

			return converter.generatePrivate(privateKeyInfo);
		}
	}

}