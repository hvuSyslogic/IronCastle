namespace org.bouncycastle.asn1.test
{

	using Restriction = org.bouncycastle.asn1.isismtt.x509.Restriction;
	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;

	public class RestrictionUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "Restriction";
		}

		public override void performTest()
		{
			DirectoryString res = new DirectoryString("test");
			Restriction restriction = new Restriction(res.getString());

			checkConstruction(restriction, res);

			try
			{
				Restriction.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(Restriction restriction, DirectoryString res)
		{
			checkValues(restriction, res);

			restriction = Restriction.getInstance(restriction);

			checkValues(restriction, res);

			ASN1InputStream aIn = new ASN1InputStream(restriction.toASN1Primitive().getEncoded());

			ASN1String str = (ASN1String)aIn.readObject();

			restriction = Restriction.getInstance(str);

			checkValues(restriction, res);
		}

		private void checkValues(Restriction restriction, DirectoryString res)
		{
			checkMandatoryField("restriction", res, restriction.getRestriction());
		}

		public static void Main(string[] args)
		{
			runTest(new RestrictionUnitTest());
		}
	}

}