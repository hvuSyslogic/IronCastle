using org.bouncycastle.asn1.gm;

namespace org.bouncycastle.jcajce.provider.asymmetric
{

	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	public class GM
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

		private static readonly Map<string, string> generalSm2Attributes = new HashMap<string, string>();

		static GM()
		{
			generalSm2Attributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
			generalSm2Attributes.put("SupportedKeyFormats", "PKCS#8|X.509");
		}

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Signature.SM3WITHSM2", PREFIX + "GMSignatureSpi$sm3WithSM2");
				provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers_Fields.sm2sign_with_sm3, "SM3WITHSM2");
			}
		}
	}

}