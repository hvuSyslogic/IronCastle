namespace org.bouncycastle.asn1.test
{

	using DeclarationOfMajority = org.bouncycastle.asn1.isismtt.x509.DeclarationOfMajority;

	public class DeclarationOfMajorityUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "DeclarationOfMajority";
		}

		public override void performTest()
		{
			ASN1GeneralizedTime dateOfBirth = new ASN1GeneralizedTime("20070315173729Z");
			DeclarationOfMajority decl = new DeclarationOfMajority(dateOfBirth);

			checkConstruction(decl, DeclarationOfMajority.dateOfBirth, dateOfBirth, -1);

			decl = new DeclarationOfMajority(6);

			checkConstruction(decl, DeclarationOfMajority.notYoungerThan_Renamed, null, 6);

			decl = DeclarationOfMajority.getInstance(null);

			if (decl != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				DeclarationOfMajority.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(DeclarationOfMajority decl, int type, ASN1GeneralizedTime dateOfBirth, int notYoungerThan)
		{
			checkValues(decl, type, dateOfBirth, notYoungerThan);

			decl = DeclarationOfMajority.getInstance(decl);

			checkValues(decl, type, dateOfBirth, notYoungerThan);

			ASN1InputStream aIn = new ASN1InputStream(decl.toASN1Primitive().getEncoded());

			DERTaggedObject info = (DERTaggedObject)aIn.readObject();

			decl = DeclarationOfMajority.getInstance(info);

			checkValues(decl, type, dateOfBirth, notYoungerThan);
		}

		private void checkValues(DeclarationOfMajority decl, int type, ASN1GeneralizedTime dateOfBirth, int notYoungerThan)
		{
			checkMandatoryField("type", type, decl.getType());
			checkOptionalField("dateOfBirth", dateOfBirth, decl.getDateOfBirth());
			if (notYoungerThan != -1 && notYoungerThan != decl.notYoungerThan())
			{
				fail("notYoungerThan mismatch");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new DeclarationOfMajorityUnitTest());
		}
	}

}