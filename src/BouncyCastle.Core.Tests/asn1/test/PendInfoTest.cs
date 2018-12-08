using System;

namespace org.bouncycastle.asn1.test
{

	using PendInfo = org.bouncycastle.asn1.cmc.PendInfo;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class PendInfoTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new PendInfoTest());
		}

		public override string getName()
		{
			return "PendInfoTest";
		}

		public override void performTest()
		{
			PendInfo info = new PendInfo("".GetBytes(), new ASN1GeneralizedTime(DateTime.Now));
			byte[] b = info.getEncoded();
			PendInfo infoResult = PendInfo.getInstance(b);

			isTrue("pendToken", areEqual(info.getPendToken(), infoResult.getPendToken()));
			isEquals("pendTime", info.getPendTime(), infoResult.getPendTime());

			try
			{
				PendInfo.getInstance(new DERSequence());
				fail("Sequence length not 2");
			}
			catch (Exception t)
			{
				isEquals("Exception type", t.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}