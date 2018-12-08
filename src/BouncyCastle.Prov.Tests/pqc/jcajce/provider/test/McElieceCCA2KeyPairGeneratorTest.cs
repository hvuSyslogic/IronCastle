using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceCCA2KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;


	public class McElieceCCA2KeyPairGeneratorTest : KeyPairGeneratorTest
	{

		public override void setUp()
		{
			base.setUp();
		}

		public virtual void testKeyFactory()
		{
			kf = KeyFactory.getInstance("McElieceKobaraImai");
			kf = KeyFactory.getInstance("McEliecePointcheval");
			kf = KeyFactory.getInstance("McElieceFujisaki");
			kf = KeyFactory.getInstance(PQCObjectIdentifiers_Fields.mcElieceCca2.getId());
		}

		public virtual void testKeyPairEncoding_9_33()
		{
			kf = KeyFactory.getInstance(PQCObjectIdentifiers_Fields.mcElieceCca2.getId());

			kpg = KeyPairGenerator.getInstance("McElieceKobaraImai");
			McElieceCCA2KeyGenParameterSpec @params = new McElieceCCA2KeyGenParameterSpec(9, 33);
			kpg.initialize(@params);
			performKeyPairEncodingTest(kpg.generateKeyPair());
		}
	}

}