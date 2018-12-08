using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.asn1.test
{
	using ESSCertIDv2 = org.bouncycastle.asn1.ess.ESSCertIDv2;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class ESSCertIDv2UnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "ESSCertIDv2";
		}

		public override void performTest()
		{
			// check getInstance on default algorithm.
			byte[] digest = new byte [256];
			ESSCertIDv2 essCertIdv2 = new ESSCertIDv2(new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256), digest);
			ASN1Primitive asn1Object = essCertIdv2.toASN1Primitive();

			ESSCertIDv2.getInstance(asn1Object);
		}

		public static void Main(string[] args)
		{
			runTest(new ESSCertIDv2UnitTest());
		}
	}
}