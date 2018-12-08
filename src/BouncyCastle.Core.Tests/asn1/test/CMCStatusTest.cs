namespace org.bouncycastle.asn1.test
{

	using CMCStatus = org.bouncycastle.asn1.cmc.CMCStatus;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class CMCStatusTest : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new CMCStatusTest());
		}

		public override string getName()
		{
			return "CMCStatusTest";
		}

		// From Page 68, CMC: Structures RFC 5272
		private static object[][] types = new object[][]
		{
			new object[] {"success", new long?(0L)},
			new object[] {"failed", new long?(2L)},
			new object[] {"pending", new long?(3L)},
			new object[] {"noSupport", new long?(4L)},
			new object[] {"confirmRequired", new long?(5L)},
			new object[] {"popRequired", new long?(6L)},
			new object[] {"partial", new long?(7L)}
		};
		private static Map typesMap = new HashMap();

		static CMCStatusTest()
		{
			for (int t = 0; t < types.Length; t++)
			{
				typesMap.put(types[t][1], types[t][0]);
			}
		}


		public override void performTest()
		{

			//
			// Check that range has changed and this test has not been updated or vice versa.
			// It is intended to act as a double check on the addition of CMCStatus presets by
			// requiring this test to be updated equally to ensure it will pass.
			//

			Field rangeField = typeof(CMCStatus).getDeclaredField("range");
			rangeField.setAccessible(true);

			Map range = (Map)rangeField.get(null);

			isEquals("Range in CMCStatus does not match test data.", range.size(), types.Length);

			for (Iterator rangeKeys = range.keySet().iterator(); rangeKeys.hasNext();)
			{
				object j = rangeKeys.next();
				if (!typesMap.containsKey(new long?(((ASN1Integer)j).getValue().longValue())))
				{
					fail("The 'range' map in CMCStatus contains a value not in the test ('typesMap') map, value was: " + j.ToString());
				}
			}


			for (Iterator typeKeys = typesMap.keySet().iterator(); typeKeys.hasNext();)
			{
				object j = typeKeys.next();
				if (!range.containsKey(new ASN1Integer(((long?)j).Value)))
				{
					fail("The 'typesMap' map in CMCStatusTest contains a value not in the CMCStatus ('range') map, value was: " + j.ToString());
				}
			}


			//
			// Test encoding / decoding
			//

			byte[] b = CMCStatus.failed.getEncoded();
			CMCStatus r = CMCStatus.getInstance(b);
			isEquals(r, CMCStatus.failed);

		}

	}

}