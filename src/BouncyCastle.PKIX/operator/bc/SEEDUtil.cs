using org.bouncycastle.asn1.kisa;

namespace org.bouncycastle.@operator.bc
{
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class SEEDUtil
	{
		internal static AlgorithmIdentifier determineKeyEncAlg()
		{
			// parameters absent
			return new AlgorithmIdentifier(KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap);
		}
	}

}