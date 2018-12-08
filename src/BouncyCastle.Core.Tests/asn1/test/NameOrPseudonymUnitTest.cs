namespace org.bouncycastle.asn1.test
{

	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;
	using NameOrPseudonym = org.bouncycastle.asn1.x509.sigi.NameOrPseudonym;

	public class NameOrPseudonymUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "NameOrPseudonym";
		}

		public override void performTest()
		{
			string pseudonym = "pseudonym";
			DirectoryString surname = new DirectoryString("surname");
			ASN1Sequence givenName = new DERSequence(new DirectoryString("givenName"));

			NameOrPseudonym id = new NameOrPseudonym(pseudonym);

			checkConstruction(id, pseudonym, null, null);

			id = new NameOrPseudonym(surname, givenName);

			checkConstruction(id, null, surname, givenName);

			id = NameOrPseudonym.getInstance(null);

			if (id != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				NameOrPseudonym.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(NameOrPseudonym id, string pseudonym, DirectoryString surname, ASN1Sequence givenName)
		{
			checkValues(id, pseudonym, surname, givenName);

			id = NameOrPseudonym.getInstance(id);

			checkValues(id, pseudonym, surname, givenName);

			ASN1InputStream aIn = new ASN1InputStream(id.toASN1Primitive().getEncoded());

			if (surname != null)
			{
				ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

				id = NameOrPseudonym.getInstance(seq);
			}
			else
			{
				ASN1String s = (ASN1String)aIn.readObject();

				id = NameOrPseudonym.getInstance(s);
			}

			checkValues(id, pseudonym, surname, givenName);
		}

		private void checkValues(NameOrPseudonym id, string pseudonym, DirectoryString surname, ASN1Sequence givenName)
		{

			if (surname != null)
			{
				checkMandatoryField("surname", surname, id.getSurname());
				checkMandatoryField("givenName", givenName, new DERSequence(id.getGivenName()[0]));
			}
			else
			{
				checkOptionalField("pseudonym", new DirectoryString(pseudonym), id.getPseudonym());
			}
		}

		public static void Main(string[] args)
		{
			runTest(new NameOrPseudonymUnitTest());
		}
	}

}