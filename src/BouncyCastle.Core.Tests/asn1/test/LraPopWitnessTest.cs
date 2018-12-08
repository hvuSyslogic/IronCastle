using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using LraPopWitness = org.bouncycastle.asn1.cmc.LraPopWitness;
	using Arrays = org.bouncycastle.util.Arrays;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class LraPopWitnessTest : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new LraPopWitnessTest());
		}

		public override string getName()
		{
			return "LraPopWitnessTest";
		}

		public override void performTest()
		{
			LraPopWitness popWitness = new LraPopWitness(new BodyPartID(10L), new DERSequence(new ASN1Integer(20L)));
			byte[] b = popWitness.getEncoded();
			LraPopWitness popWitnessResult = LraPopWitness.getInstance(b);

			isTrue("BodyIds", Arrays.areEqual(popWitness.getBodyIds(), popWitnessResult.getBodyIds()));
			isEquals("PkiDataBody", popWitness.getPkiDataBodyid(), popWitnessResult.getPkiDataBodyid());

			try
			{
				LraPopWitness.getInstance(new DERSequence());
				fail("Sequence length must be 2");
			}
			catch (Exception t)
			{
				isEquals("Exception class",t.GetType(), typeof(IllegalArgumentException));
			}
		}
	}

}