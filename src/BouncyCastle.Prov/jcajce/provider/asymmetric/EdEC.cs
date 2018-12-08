using org.bouncycastle.asn1.edec;

namespace org.bouncycastle.jcajce.provider.asymmetric
{

	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using KeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	public class EdEC
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".edec.";

		private static readonly Map<string, string> edxAttributes = new HashMap<string, string>();

		static EdEC()
		{
			edxAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
			edxAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
		}

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.XDH", PREFIX + "KeyFactorySpi$XDH");
				provider.addAlgorithm("KeyFactory.X448", PREFIX + "KeyFactorySpi$X448");
				provider.addAlgorithm("KeyFactory.X25519", PREFIX + "KeyFactorySpi$X25519");

				provider.addAlgorithm("KeyFactory.EDDSA", PREFIX + "KeyFactorySpi$EDDSA");
				provider.addAlgorithm("KeyFactory.ED448", PREFIX + "KeyFactorySpi$ED448");
				provider.addAlgorithm("KeyFactory.ED25519", PREFIX + "KeyFactorySpi$ED25519");

				provider.addAlgorithm("Signature.EDDSA", PREFIX + "SignatureSpi$EdDSA");
				provider.addAlgorithm("Signature.ED448", PREFIX + "SignatureSpi$Ed448");
				provider.addAlgorithm("Signature.ED25519", PREFIX + "SignatureSpi$Ed25519");
				provider.addAlgorithm("Signature", EdECObjectIdentifiers_Fields.id_Ed448, PREFIX + "SignatureSpi$Ed448");
				provider.addAlgorithm("Signature", EdECObjectIdentifiers_Fields.id_Ed25519, PREFIX + "SignatureSpi$Ed25519");

				provider.addAlgorithm("KeyPairGenerator.EDDSA", PREFIX + "KeyPairGeneratorSpi$EdDSA");
				provider.addAlgorithm("KeyPairGenerator.ED448", PREFIX + "KeyPairGeneratorSpi$Ed448");
				provider.addAlgorithm("KeyPairGenerator.ED25519", PREFIX + "KeyPairGeneratorSpi$Ed25519");
				provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers_Fields.id_Ed448, PREFIX + "KeyPairGeneratorSpi$Ed448");
				provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers_Fields.id_Ed25519, PREFIX + "KeyPairGeneratorSpi$Ed25519");

				provider.addAlgorithm("KeyAgreement.XDH", PREFIX + "KeyAgreementSpi$XDH");
				provider.addAlgorithm("KeyAgreement.X448", PREFIX + "KeyAgreementSpi$X448");
				provider.addAlgorithm("KeyAgreement.X25519", PREFIX + "KeyAgreementSpi$X25519");
				provider.addAlgorithm("KeyAgreement", EdECObjectIdentifiers_Fields.id_X448, PREFIX + "KeyAgreementSpi$X448");
				provider.addAlgorithm("KeyAgreement", EdECObjectIdentifiers_Fields.id_X25519, PREFIX + "KeyAgreementSpi$X25519");

				provider.addAlgorithm("KeyAgreement.X25519WITHSHA256CKDF", PREFIX + "KeyAgreementSpi$X25519withSHA256CKDF");
				provider.addAlgorithm("KeyAgreement.X448WITHSHA512CKDF", PREFIX + "KeyAgreementSpi$X448withSHA512CKDF");

				provider.addAlgorithm("KeyAgreement.X25519WITHSHA256KDF", PREFIX + "KeyAgreementSpi$X25519withSHA256KDF");
				provider.addAlgorithm("KeyAgreement.X448WITHSHA512KDF", PREFIX + "KeyAgreementSpi$X448withSHA512KDF");

				provider.addAlgorithm("KeyAgreement.X25519UWITHSHA256KDF", PREFIX + "KeyAgreementSpi$X25519UwithSHA256KDF");
				provider.addAlgorithm("KeyAgreement.X448UWITHSHA512KDF", PREFIX + "KeyAgreementSpi$X448UwithSHA512KDF");

				provider.addAlgorithm("KeyPairGenerator.XDH", PREFIX + "KeyPairGeneratorSpi$XDH");
				provider.addAlgorithm("KeyPairGenerator.X448", PREFIX + "KeyPairGeneratorSpi$X448");
				provider.addAlgorithm("KeyPairGenerator.X25519", PREFIX + "KeyPairGeneratorSpi$X25519");
				provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers_Fields.id_X448, PREFIX + "KeyPairGeneratorSpiSpi$X448");
				provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers_Fields.id_X25519, PREFIX + "KeyPairGeneratorSpiSpi$X25519");

				registerOid(provider, EdECObjectIdentifiers_Fields.id_X448, "XDH", new KeyFactorySpi.X448());
				registerOid(provider, EdECObjectIdentifiers_Fields.id_X25519, "XDH", new KeyFactorySpi.X25519());
				registerOid(provider, EdECObjectIdentifiers_Fields.id_Ed448, "EDDSA", new KeyFactorySpi.ED448());
				registerOid(provider, EdECObjectIdentifiers_Fields.id_Ed25519, "EDDSA", new KeyFactorySpi.ED25519());
			}
		}
	}

}