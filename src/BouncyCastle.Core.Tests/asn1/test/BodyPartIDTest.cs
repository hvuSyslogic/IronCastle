using System;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class BodyPartIDTest : SimpleTest
	{


		public override void performTest()
		{
			// Test correct encode / decode


			{
				// Test encode and decode from Long and from other instance of BodyPartID
				BodyPartID bpd = new BodyPartID(10L);
				byte[] b = bpd.getEncoded();
				BodyPartID resBpd = BodyPartID.getInstance(b);
				isEquals("Correct / Encode byte array", resBpd.getID(), bpd.getID());

				BodyPartID rootPartID = new BodyPartID(12L);
				bpd = BodyPartID.getInstance(rootPartID);
				b = bpd.getEncoded();
				resBpd = BodyPartID.getInstance(b);
				isEquals("Correct / Encode byte array", resBpd.getID(), rootPartID.getID());
			}


			{
				// Test lower limit, should not throw exception
				try
				{
					new BodyPartID(0);
				}
				catch (Exception t)
				{
					fail("Unexpected exception: " + t.Message, t);
				}

				// Test below lower range
				try
				{
					new BodyPartID(-1);
					fail("Expecting IllegalArgumentException because of outside lower range");
				}
				catch (Exception e)
				{
					if (!(e is IllegalArgumentException))
					{
						fail("Expecting only IllegalArgumentException, got:" + e.Message, e);
					}
				}
			}

			{
				// Test upper limit, should not throw exception.
				try
				{
					new BodyPartID(4294967295L);
				}
				catch (Exception t)
				{
					fail("Unexpected exception: " + t.Message, t);
				}

				// Test above upper range
				try
				{
					new BodyPartID(4294967296L);
					fail("Expecting IllegalArgumentException because of outside upper range");
				}
				catch (Exception e)
				{
					if (!(e is IllegalArgumentException))
					{
						fail("Expecting only IllegalArgumentException, got:" + e.Message, e);
					}
				}
			}
		}

		public override string getName()
		{
			return "BodyPartIDTest";
		}

		public static void Main(string[] args)
		{
			runTest(new BodyPartIDTest());
		}
	}


}