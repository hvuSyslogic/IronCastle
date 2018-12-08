using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using DecryptedPOP = org.bouncycastle.asn1.cmc.DecryptedPOP;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class DecryptedPOPTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new DecryptedPOPTest());
		}

		public override string getName()
		{
			return "DecryptedPOPTest";
		}

		public override void performTest()
		{
			AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.9.8.7.6")); // Not real!
			DecryptedPOP pop = new DecryptedPOP(new BodyPartID(10L), algId, "cats".GetBytes());
			byte[] b = pop.getEncoded();
			DecryptedPOP popResult = DecryptedPOP.getInstance(b);
			isEquals("Bodypart id", popResult.getBodyPartID(), pop.getBodyPartID());
			isTrue("The POP", Arrays.areEqual(popResult.getThePOP(), pop.getThePOP()));
			isEquals("POP Result", popResult.getThePOPAlgID(), pop.getThePOPAlgID());

			try
			{
				DecryptedPOP.getInstance(new DERSequence(new BodyPartID(10L)));
				fail("Sequence must be 3 elements long");
			}
			catch (Exception t)
			{
				isEquals(t.GetType(), typeof(IllegalArgumentException));
			}
		}
	}

}