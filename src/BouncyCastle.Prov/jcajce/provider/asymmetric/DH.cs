using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.jcajce.provider.asymmetric
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using KeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.dh.KeyFactorySpi;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	public class DH
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dh.";

		private static readonly Map<string, string> generalDhAttributes = new HashMap<string, string>();

		static DH()
		{
			generalDhAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
			generalDhAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
		}

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyPairGenerator.DH", PREFIX + "KeyPairGeneratorSpi");
				provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");

				provider.addAttributes("KeyAgreement.DH", generalDhAttributes);
				provider.addAlgorithm("KeyAgreement.DH", PREFIX + "KeyAgreementSpi");
				provider.addAlgorithm("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");
				provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers_Fields.id_alg_ESDH, PREFIX + "KeyAgreementSpi$DHwithRFC2631KDF");
				provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers_Fields.id_alg_SSDH, PREFIX + "KeyAgreementSpi$DHwithRFC2631KDF");

				provider.addAlgorithm("KeyFactory.DH", PREFIX + "KeyFactorySpi");
				provider.addAlgorithm("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");

				provider.addAlgorithm("AlgorithmParameters.DH", PREFIX + "AlgorithmParametersSpi");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");

				provider.addAlgorithm("AlgorithmParameterGenerator.DH", PREFIX + "AlgorithmParameterGeneratorSpi");

				provider.addAlgorithm("Cipher.IES", PREFIX + "IESCipher$IES");
				provider.addAlgorithm("Cipher.IESwithAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
				provider.addAlgorithm("Cipher.IESWITHAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
				provider.addAlgorithm("Cipher.IESWITHDESEDE-CBC", PREFIX + "IESCipher$IESwithDESedeCBC");

				provider.addAlgorithm("Cipher.DHIES", PREFIX + "IESCipher$IES");
				provider.addAlgorithm("Cipher.DHIESwithAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
				provider.addAlgorithm("Cipher.DHIESWITHAES-CBC", PREFIX + "IESCipher$IESwithAESCBC");
				provider.addAlgorithm("Cipher.DHIESWITHDESEDE-CBC", PREFIX + "IESCipher$IESwithDESedeCBC");

				provider.addAlgorithm("KeyAgreement.DHWITHSHA1KDF", PREFIX + "KeyAgreementSpi$DHwithSHA1KDF");
				provider.addAlgorithm("KeyAgreement.DHWITHSHA224KDF", PREFIX + "KeyAgreementSpi$DHwithSHA224KDF");
				provider.addAlgorithm("KeyAgreement.DHWITHSHA256KDF", PREFIX + "KeyAgreementSpi$DHwithSHA256KDF");
				provider.addAlgorithm("KeyAgreement.DHWITHSHA384KDF", PREFIX + "KeyAgreementSpi$DHwithSHA384KDF");
				provider.addAlgorithm("KeyAgreement.DHWITHSHA512KDF", PREFIX + "KeyAgreementSpi$DHwithSHA512KDF");

				provider.addAlgorithm("KeyAgreement.DHUWITHSHA1KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA1KDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA224KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA224KDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA256KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA256KDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA384KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA384KDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA512KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA512KDF");

				provider.addAlgorithm("KeyAgreement.DHUWITHSHA1CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA1CKDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA224CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA224CKDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA256CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA256CKDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA384CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA384CKDF");
				provider.addAlgorithm("KeyAgreement.DHUWITHSHA512CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA512CKDF");

				provider.addAlgorithm("KeyAgreement.MQVWITHSHA1KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA1KDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA224KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA224KDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA256KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA256KDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA384KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA384KDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA512KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA512KDF");

				provider.addAlgorithm("KeyAgreement.MQVWITHSHA1CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA1CKDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA224CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA224CKDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA256CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA256CKDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA384CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA384CKDF");
				provider.addAlgorithm("KeyAgreement.MQVWITHSHA512CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA512CKDF");

				registerOid(provider, PKCSObjectIdentifiers_Fields.dhKeyAgreement, "DH", new KeyFactorySpi());
				registerOid(provider, X9ObjectIdentifiers_Fields.dhpublicnumber, "DH", new KeyFactorySpi());
			}
		}
	}

}