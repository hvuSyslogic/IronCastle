using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using QTESLAKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;

	public class QTESLA
	{
		private const string PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".qtesla.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.QTESLA", PREFIX + "QTESLAKeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.QTESLA", PREFIX + "KeyPairGeneratorSpi");

				provider.addAlgorithm("Signature.QTESLA", PREFIX + "SignatureSpi$qTESLA");

				addSignatureAlgorithm(provider,"QTESLA-I", PREFIX + "SignatureSpi$HeuristicI", PQCObjectIdentifiers_Fields.qTESLA_I);
				addSignatureAlgorithm(provider,"QTESLA-III-SIZE", PREFIX + "SignatureSpi$HeuristicIIISize", PQCObjectIdentifiers_Fields.qTESLA_III_size);
				addSignatureAlgorithm(provider,"QTESLA-III-SPEED", PREFIX + "SignatureSpi$HeuristicIIISpeed", PQCObjectIdentifiers_Fields.qTESLA_III_speed);
				addSignatureAlgorithm(provider,"QTESLA-P-I", PREFIX + "SignatureSpi$ProvablySecureI", PQCObjectIdentifiers_Fields.qTESLA_p_I);
				addSignatureAlgorithm(provider,"QTESLA-P-III", PREFIX + "SignatureSpi$ProvablySecureIII", PQCObjectIdentifiers_Fields.qTESLA_p_III);

				AsymmetricKeyInfoConverter keyFact = new QTESLAKeyFactorySpi();

				registerOid(provider, PQCObjectIdentifiers_Fields.qTESLA_I, "QTESLA-I", keyFact);
				registerOid(provider, PQCObjectIdentifiers_Fields.qTESLA_III_size, "QTESLA-III-SIZE", keyFact);
				registerOid(provider, PQCObjectIdentifiers_Fields.qTESLA_III_speed, "QTESLA-III-SPEED", keyFact);
				registerOid(provider, PQCObjectIdentifiers_Fields.qTESLA_p_I, "QTESLA-P-I", keyFact);
				registerOid(provider, PQCObjectIdentifiers_Fields.qTESLA_p_III, "QTESLA-P-III", keyFact);
			}
		}
	}

}