namespace org.bouncycastle.asn1.test
{

	using PollReqContent = org.bouncycastle.asn1.cmp.PollReqContent;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PollReqContentTest : SimpleTest
	{
		public override string getName()
		{
			return "PollReqContentTest";
		}

		public override void performTest()
		{
			BigInteger one = BigInteger.valueOf(1), two = BigInteger.valueOf(2);
			BigInteger[] ids = new BigInteger[] {one, two};

			PollReqContent c = new PollReqContent(ids);

			ASN1Integer[][] vs = c.getCertReqIds();

			isTrue(vs.Length == 2);
			for (int i = 0; i != vs.Length; i++)
			{
				isTrue(vs[i].Length == 1);
				isTrue(vs[i][0].getValue().Equals(ids[i]));
			}

			BigInteger[] values = c.getCertReqIdValues();

			isTrue(values.Length == 2);
			for (int i = 0; i != values.Length; i++)
			{
				isTrue(values[i].Equals(ids[i]));
			}

			c = new PollReqContent(two);
			vs = c.getCertReqIds();

			isTrue(vs.Length == 1);

			isTrue(vs[0].Length == 1);
			isTrue(vs[0][0].getValue().Equals(two));
		}

		public static void Main(string[] args)
		{
			runTest(new PollReqContentTest());
		}
	}

}