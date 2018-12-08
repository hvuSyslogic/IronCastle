using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;


	/// <summary>
	/// KeyFactory/KeyPairGenerator tests for NewHope (NH) with the BCPQC provider.
	/// </summary>
	public class NewHopeKeyPairGeneratorTest : KeyPairGeneratorTest
	{

		public override void setUp()
		{
			base.setUp();
		}

		public virtual void testKeyFactory()
		{
			kf = KeyFactory.getInstance("NH", "BCPQC");
			kf = KeyFactory.getInstance(PQCObjectIdentifiers_Fields.newHope.getId(), "BCPQC");
		}

		public virtual void testKeyPairEncoding()
		{
			kf = KeyFactory.getInstance("NH", "BCPQC");

			kpg = KeyPairGenerator.getInstance("NH", "BCPQC");
			kpg.initialize(1024, new SecureRandom());

			performKeyPairEncodingTest(kpg.generateKeyPair());
		}

	}

}