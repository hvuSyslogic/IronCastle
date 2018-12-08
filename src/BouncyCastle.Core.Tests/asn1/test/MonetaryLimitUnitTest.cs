namespace org.bouncycastle.asn1.test
{

	using MonetaryLimit = org.bouncycastle.asn1.isismtt.x509.MonetaryLimit;

	public class MonetaryLimitUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "MonetaryLimit";
		}

		public override void performTest()
		{
			string currency = "AUD";
			int amount = 1;
			int exponent = 2;

			MonetaryLimit limit = new MonetaryLimit(currency, amount, exponent);

			checkConstruction(limit, currency, amount, exponent);

			limit = MonetaryLimit.getInstance(null);

			if (limit != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				MonetaryLimit.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(MonetaryLimit limit, string currency, int amount, int exponent)
		{
			checkValues(limit, currency, amount, exponent);

			limit = MonetaryLimit.getInstance(limit);

			checkValues(limit, currency, amount, exponent);

			ASN1InputStream aIn = new ASN1InputStream(limit.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			limit = MonetaryLimit.getInstance(seq);

			checkValues(limit, currency, amount, exponent);
		}

		private void checkValues(MonetaryLimit limit, string currency, int amount, int exponent)
		{
			checkMandatoryField("currency", currency, limit.getCurrency());
			checkMandatoryField("amount", amount, limit.getAmount().intValue());
			checkMandatoryField("exponent", exponent, limit.getExponent().intValue());
		}

		public static void Main(string[] args)
		{
			runTest(new MonetaryLimitUnitTest());
		}
	}

}