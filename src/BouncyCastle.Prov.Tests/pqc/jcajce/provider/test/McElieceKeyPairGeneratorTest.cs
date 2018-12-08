using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceKeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;


	public class McElieceKeyPairGeneratorTest : KeyPairGeneratorTest
	{

		public override void setUp()
		{
			base.setUp();
		}

		public virtual void testKeyFactory()
		{
			kf = KeyFactory.getInstance("McEliece");
			kf = KeyFactory.getInstance(PQCObjectIdentifiers_Fields.mcEliece.getId());
		}

		public virtual void testKeyPairEncoding_9_33()
		{
			kf = KeyFactory.getInstance("McEliece");

			kpg = KeyPairGenerator.getInstance("McEliece");
			McElieceKeyGenParameterSpec @params = new McElieceKeyGenParameterSpec(9, 33);
			kpg.initialize(@params);
			performKeyPairEncodingTest(kpg.generateKeyPair());
		}

	}

}