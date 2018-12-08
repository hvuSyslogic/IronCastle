using System;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using BodyPartPath = org.bouncycastle.asn1.cmc.BodyPartPath;
	using BodyPartReference = org.bouncycastle.asn1.cmc.BodyPartReference;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class BodyPartReferenceTest : SimpleTest
	{

		public override string getName()
		{
			return "BodyPartReferenceTest";
		}

		public override void performTest()
		{
			Random rand = new Random();
			BodyPartReference ch0 = null;
			BodyPartReference ch1 = null;
			{
				// Choice 1
				BodyPartID id = new BodyPartID(Math.Abs(rand.nextLong() % 4294967295L));

				ch0 = new BodyPartReference(id);
				byte[] b = ch0.getEncoded();

				BodyPartReference brRes = BodyPartReference.getInstance(b);
				isEquals(brRes, ch0);
			}

			{
				// Choice 2

				BodyPartID[] bpid = new BodyPartID[Math.Abs(rand.nextInt()) % 20];
				for (int t = 0; t < bpid.Length; t++)
				{
					bpid[t] = new BodyPartID(Math.Abs(rand.nextLong() % 4294967295L));
				}

				ch1 = new BodyPartReference(new BodyPartPath(bpid));
				byte[] b = ch1.getEncoded();

				BodyPartReference brRes = BodyPartReference.getInstance(b);
				isEquals(brRes, ch1);
			}


			{
				// Test choice alternatives are not equal.
				BodyPartID id = new BodyPartID(Math.Abs(rand.nextLong() % 4294967295L));

				ch0 = new BodyPartReference(id);
				ch1 = new BodyPartReference(new BodyPartPath(id));

				try
				{
					isEquals(ch0, ch1);
					fail("Must not be equal.");
				}
				catch (Exception)
				{
					// Ignored
				}
			}

		}

		public static void Main(string[] args)
		{
			runTest(new BodyPartReferenceTest());
		}

	}

}