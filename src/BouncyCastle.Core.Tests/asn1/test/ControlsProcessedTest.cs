using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using BodyPartReference = org.bouncycastle.asn1.cmc.BodyPartReference;
	using ControlsProcessed = org.bouncycastle.asn1.cmc.ControlsProcessed;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class ControlsProcessedTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new ControlsProcessedTest());
		}

		public override string getName()
		{
			return "ControlsProcessedTest";
		}

		public override void performTest()
		{
			ControlsProcessed cp = new ControlsProcessed(new BodyPartReference[]
			{
				new BodyPartReference(new BodyPartID(12L)),
				new BodyPartReference(new BodyPartID(14L))
			});
			byte[] b = cp.getEncoded();
			ControlsProcessed cpResult = ControlsProcessed.getInstance(b);
			isTrue(cpResult.getBodyList().Length == cp.getBodyList().Length);
			isEquals(cpResult.getBodyList()[0], cp.getBodyList()[0]);
			isEquals(cpResult.getBodyList()[1], cp.getBodyList()[1]);

			//
			// Incorrect sequence size.
			//

			try
			{
				ControlsProcessed.getInstance(new DERSequence(new ASN1Encodable[]
				{
					new ASN1Integer(12L),
					new DERUTF8String("Monkeys")
				}));
				fail("Must accept only sequence length of 1");
			}
			catch (Exception t)
			{
				isEquals(t.GetType(), typeof(IllegalArgumentException));
			}
		}

	}

}