using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using SPHINCS256KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;


	/// <summary>
	/// KeyFactory/KeyPairGenerator tests for SPHINCS-256 with the BCPQC provider.
	/// </summary>
	public class Sphincs256KeyPairGeneratorTest : KeyPairGeneratorTest
	{

		public override void setUp()
		{
			base.setUp();
		}

		public virtual void testKeyFactory()
		{
			kf = KeyFactory.getInstance("SPHINCS256", "BCPQC");
			kf = KeyFactory.getInstance(PQCObjectIdentifiers_Fields.newHope.getId(), "BCPQC");
		}

		public virtual void testKeyPairEncoding()
		{
			kf = KeyFactory.getInstance("SPHINCS256", "BCPQC");

			kpg = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");
			kpg.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256), new SecureRandom());
			performKeyPairEncodingTest(kpg.generateKeyPair());
		}

	}

}