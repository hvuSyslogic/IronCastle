namespace org.bouncycastle.asn1.test
{

	using CMCFailInfo = org.bouncycastle.asn1.cmc.CMCFailInfo;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CMCFailInfoTest : SimpleTest
	{

		// From Page 68, CMC: Structures RFC 5272
		private static object[][] types = new object[][]
		{
			new object[] {"badAlg", new long?(0L)},
			new object[] {"badMessageCheck", new long?(1L)},
			new object[] {"badRequest", new long?(2L)},
			new object[] {"badTime", new long?(3L)},
			new object[] {"badCertId", new long?(4L)},
			new object[] {"unsupportedExt", new long?(5L)},
			new object[] {"mustArchiveKeys", new long?(6L)},
			new object[] {"badIdentity", new long?(7L)},
			new object[] {"popRequired", new long?(8L)},
			new object[] {"popFailed", new long?(9L)},
			new object[] {"noKeyReuse", new long?(10L)},
			new object[] {"internalCAError", new long?(11L)},
			new object[] {"tryLater", new long?(12L)},
			new object[] {"authDataFail", new long?(13L)}
		};
		private static Map typesMap = new HashMap();

		static CMCFailInfoTest()
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
			// It is intended to act as a double check on the addition of CMCFailInfo presets by
			// requiring this test to be updated equally to ensure it will pass.
			//

			Field rangeField = typeof(CMCFailInfo).getDeclaredField("range");
			rangeField.setAccessible(true);

			Map range = (Map)rangeField.get(null);

			isEquals("Range in CMCFailInfo does not match test data.",range.size(), types.Length);

			for (Iterator rangeKeys = range.keySet().iterator(); rangeKeys.hasNext();)
			{
				object j = rangeKeys.next();
				if (!typesMap.containsKey(new long?(((ASN1Integer)j).getValue().longValue())))
				{
					fail("The 'range' map in CMCFailInfo contains a value not in the test ('typesMap') map, value was: " + j.ToString());
				}
			}


			for (Iterator typeKeys = typesMap.keySet().iterator(); typeKeys.hasNext();)
			{
				object j = typeKeys.next();
				if (!range.containsKey(new ASN1Integer(((long?)j).Value)))
				{
					fail("The 'typesMap' map in CMCFailInfoTest contains a value not in the CMCFailInfo ('range') map, value was: " + j.ToString());
				}
			}


			//
			// Test encoding / decoding
			//

			byte[] b = CMCFailInfo.authDataFail.getEncoded();
			CMCFailInfo r = CMCFailInfo.getInstance(b);
			isEquals(r,CMCFailInfo.authDataFail);

		}

		public override string getName()
		{
			return "CMCFailInfoTest";
		}

		public static void Main(string[] args)
		{
			runTest(new CMCFailInfoTest());
		}
	}

}