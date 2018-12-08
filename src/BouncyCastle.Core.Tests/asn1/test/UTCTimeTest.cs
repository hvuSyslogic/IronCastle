namespace org.bouncycastle.asn1.test
{
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	/// <summary>
	/// X.690 test example
	/// </summary>
	public class UTCTimeTest : SimpleTest
	{
		internal string[] input = new string[] {"020122122220Z", "020122122220-1000", "020122122220+1000", "020122122220+00", "0201221222Z", "0201221222-1000", "0201221222+1000", "0201221222+00", "550122122220Z", "5501221222Z"};

		internal string[] output = new string[] {"20020122122220GMT+00:00", "20020122122220GMT-10:00", "20020122122220GMT+10:00", "20020122122220GMT+00:00", "20020122122200GMT+00:00", "20020122122200GMT-10:00", "20020122122200GMT+10:00", "20020122122200GMT+00:00", "19550122122220GMT+00:00", "19550122122200GMT+00:00"};

		internal string[] zOutput1 = new string[] {"20020122122220Z", "20020122222220Z", "20020122022220Z", "20020122122220Z", "20020122122200Z", "20020122222200Z", "20020122022200Z", "20020122122200Z", "19550122122220Z", "19550122122200Z"};

		internal string[] zOutput2 = new string[] {"20020122122220Z", "20020122222220Z", "20020122022220Z", "20020122122220Z", "20020122122200Z", "20020122222200Z", "20020122022200Z", "20020122122200Z", "19550122122220Z", "19550122122200Z"};

		public override string getName()
		{
			return "UTCTime";
		}

		public override void performTest()
		{
			SimpleDateFormat yyyyF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
			SimpleDateFormat yyF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

			yyyyF.setTimeZone(new SimpleTimeZone(0,"Z"));
			yyF.setTimeZone(new SimpleTimeZone(0,"Z"));

			for (int i = 0; i != input.Length; i++)
			{
				DERUTCTime t = new DERUTCTime(input[i]);

				if (!t.getAdjustedTime().Equals(output[i]))
				{
					fail("failed conversion test " + i);
				}

				if (!yyyyF.format(t.getAdjustedDate()).Equals(zOutput1[i]))
				{
					fail("failed date conversion test " + i);
				}

				if (!yyF.format(t.getDate()).Equals(zOutput2[i]))
				{
					fail("failed date shortened conversion test " + i);
				}
			}
		}

		public static void Main(string[] args)
		{
			runTest(new UTCTimeTest());
		}
	}

}