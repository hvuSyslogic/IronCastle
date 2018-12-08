using System;

namespace org.bouncycastle.asn1.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// X.690 test example
	/// </summary>
	public class GeneralizedTimeTest : SimpleTest
	{
		internal string[] input = new string[] {"20020122122220", "20020122122220Z", "20020122122220-1000", "20020122122220+00", "20020122122220.1", "20020122122220.1Z", "20020122122220.1-1000", "20020122122220.1+00", "20020122122220.01", "20020122122220.01Z", "20020122122220.01-1000", "20020122122220.01+00", "20020122122220.001", "20020122122220.001Z", "20020122122220.001-1000", "20020122122220.001+00", "20020122122220.0001", "20020122122220.0001Z", "20020122122220.0001-1000", "20020122122220.0001+00", "20020122122220.0001+1000"};

		internal string[] output = new string[] {"20020122122220", "20020122122220GMT+00:00", "20020122122220GMT-10:00", "20020122122220GMT+00:00", "20020122122220.1", "20020122122220.1GMT+00:00", "20020122122220.1GMT-10:00", "20020122122220.1GMT+00:00", "20020122122220.01", "20020122122220.01GMT+00:00", "20020122122220.01GMT-10:00", "20020122122220.01GMT+00:00", "20020122122220.001", "20020122122220.001GMT+00:00", "20020122122220.001GMT-10:00", "20020122122220.001GMT+00:00", "20020122122220.0001", "20020122122220.0001GMT+00:00", "20020122122220.0001GMT-10:00", "20020122122220.0001GMT+00:00", "20020122122220.0001GMT+10:00"};

		internal string[] zOutput = new string[] {"20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122022220Z"};

		internal string[] mzOutput = new string[] {"20020122122220.000Z", "20020122122220.000Z", "20020122222220.000Z", "20020122122220.000Z", "20020122122220.100Z", "20020122122220.100Z", "20020122222220.100Z", "20020122122220.100Z", "20020122122220.010Z", "20020122122220.010Z", "20020122222220.010Z", "20020122122220.010Z", "20020122122220.001Z", "20020122122220.001Z", "20020122222220.001Z", "20020122122220.001Z", "20020122122220.000Z", "20020122122220.000Z", "20020122222220.000Z", "20020122122220.000Z", "20020122022220.000Z"};

		internal string[] derMzOutput = new string[] {"20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122122220.1Z", "20020122122220.1Z", "20020122222220.1Z", "20020122122220.1Z", "20020122122220.01Z", "20020122122220.01Z", "20020122222220.01Z", "20020122122220.01Z", "20020122122220.001Z", "20020122122220.001Z", "20020122222220.001Z", "20020122122220.001Z", "20020122122220Z", "20020122122220Z", "20020122222220Z", "20020122122220Z", "20020122022220Z"};

		internal string[] truncOutput = new string[] {"200201221222Z", "2002012212Z"};

		 internal string[] derTruncOutput = new string[] {"20020122122200Z", "20020122120000Z"};

		public override string getName()
		{
			return "GeneralizedTime";
		}

		public override void performTest()
		{
			SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			for (int i = 0; i != input.Length; i++)
			{
				ASN1GeneralizedTime t = new ASN1GeneralizedTime(input[i]);

				if (output[i].IndexOf('G') > 0) // don't check local time the same way
				{
					if (!t.getTime().Equals(output[i]))
					{
						fail("failed conversion test");
					}
					if (!dateF.format(t.getDate()).Equals(zOutput[i]))
					{
						fail("failed date conversion test");
					}
				}
				else
				{
					string offset = calculateGMTOffset(t.getDate());
					if (!t.getTime().Equals(output[i] + offset))
					{
						fail("failed conversion test");
					}
				}
			}

			dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");

			dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

			for (int i = 0; i != input.Length; i++)
			{
				ASN1GeneralizedTime t = new ASN1GeneralizedTime(input[i]);

				if (!dateF.format(t.getDate()).Equals(mzOutput[i]))
				{
					fail("failed long date conversion test");
				}
			}

			for (int i = 0; i != mzOutput.Length; i++)
			{
				ASN1GeneralizedTime t = new DERGeneralizedTime(mzOutput[i]);

				if (!areEqual(t.getEncoded(), (new ASN1GeneralizedTime(derMzOutput[i])).getEncoded()))
				{
					fail("der encoding wrong");
				}
			}

			for (int i = 0; i != truncOutput.Length; i++)
			{
				DERGeneralizedTime t = new DERGeneralizedTime(truncOutput[i]);

				if (!areEqual(t.getEncoded(), (new ASN1GeneralizedTime(derTruncOutput[i])).getEncoded()))
				{
					fail("trunc der encoding wrong");
				}
			}
		}

		private string calculateGMTOffset(DateTime date)
		{
			string sign = "+";
			TimeZone timeZone = TimeZone.getDefault();
			int offset = timeZone.getRawOffset();
			if (offset < 0)
			{
				sign = "-";
				offset = -offset;
			}
			int hours = offset / (60 * 60 * 1000);
			int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

			if (timeZone.useDaylightTime() && timeZone.inDaylightTime(date))
			{
				hours += sign.Equals("+") ? 1 : -1;
			}

			return "GMT" + sign + convert(hours) + ":" + convert(minutes);
		}

		private string convert(int time)
		{
			if (time < 10)
			{
				return "0" + time;
			}

			return Convert.ToString(time);
		}

		public static void Main(string[] args)
		{
			runTest(new GeneralizedTimeTest());
		}
	}

}