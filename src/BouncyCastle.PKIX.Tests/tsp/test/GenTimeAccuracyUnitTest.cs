namespace org.bouncycastle.tsp.test
{
	using TestCase = junit.framework.TestCase;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using Accuracy = org.bouncycastle.asn1.tsp.Accuracy;

	public class GenTimeAccuracyUnitTest : TestCase
	{
		private static readonly ASN1Integer ZERO_VALUE = new ASN1Integer(0);
		private static readonly ASN1Integer ONE_VALUE = new ASN1Integer(1);
		private static readonly ASN1Integer TWO_VALUE = new ASN1Integer(2);
		private static readonly ASN1Integer THREE_VALUE = new ASN1Integer(3);

		public virtual void testOneTwoThree()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, TWO_VALUE, THREE_VALUE));

			checkValues(accuracy, ONE_VALUE, TWO_VALUE, THREE_VALUE);

			checkToString(accuracy, "1.002003");
		}

		public virtual void testThreeTwoOne()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, ONE_VALUE));

			checkValues(accuracy, THREE_VALUE, TWO_VALUE, ONE_VALUE);

			checkToString(accuracy, "3.002001");
		}

		public virtual void testTwoThreeTwo()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(TWO_VALUE, THREE_VALUE, TWO_VALUE));

			checkValues(accuracy, TWO_VALUE, THREE_VALUE, TWO_VALUE);

			checkToString(accuracy, "2.003002");
		}


		public virtual void testZeroTwoThree()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, TWO_VALUE, THREE_VALUE));

			checkValues(accuracy, ZERO_VALUE, TWO_VALUE, THREE_VALUE);

			checkToString(accuracy, "0.002003");
		}

		public virtual void testThreeTwoNull()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(THREE_VALUE, TWO_VALUE, null));

			checkValues(accuracy, THREE_VALUE, TWO_VALUE, ZERO_VALUE);

			checkToString(accuracy, "3.002000");
		}

		public virtual void testOneNullOne()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ONE_VALUE, null, ONE_VALUE));

			checkValues(accuracy, ONE_VALUE, ZERO_VALUE, ONE_VALUE);

			checkToString(accuracy, "1.000001");
		}

		public virtual void testZeroNullNull()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(ZERO_VALUE, null, null));

			checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);

			checkToString(accuracy, "0.000000");
		}

		public virtual void testNullNullNull()
		{
			GenTimeAccuracy accuracy = new GenTimeAccuracy(new Accuracy(null, null, null));

			checkValues(accuracy, ZERO_VALUE, ZERO_VALUE, ZERO_VALUE);

			checkToString(accuracy, "0.000000");
		}

		private void checkValues(GenTimeAccuracy accuracy, ASN1Integer secs, ASN1Integer millis, ASN1Integer micros)
		{
			assertEquals(secs.getValue().intValue(), accuracy.getSeconds());
			assertEquals(millis.getValue().intValue(), accuracy.getMillis());
			assertEquals(micros.getValue().intValue(), accuracy.getMicros());
		}

		private void checkToString(GenTimeAccuracy accuracy, string expected)
		{
			assertEquals(expected, accuracy.ToString());
		}
	}

}