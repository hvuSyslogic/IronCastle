namespace org.bouncycastle.asn1.test
{

	using Admissions = org.bouncycastle.asn1.isismtt.x509.Admissions;
	using NamingAuthority = org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
	using ProfessionInfo = org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class AdmissionsUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "Admissions";
		}

		public override void performTest()
		{
			GeneralName name = new GeneralName(new X500Name("CN=hello world"));
			NamingAuthority auth = new NamingAuthority(new ASN1ObjectIdentifier("1.2.3"), "url", new DirectoryString("fred"));
			Admissions admissions = new Admissions(name, auth, new ProfessionInfo[0]);

			checkConstruction(admissions, name, auth);

			admissions = Admissions.getInstance(null);

			if (admissions != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				Admissions.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(Admissions admissions, GeneralName name, NamingAuthority auth)
		{
			checkValues(admissions, name, auth);

			admissions = Admissions.getInstance(admissions);

			checkValues(admissions, name, auth);

			ASN1InputStream aIn = new ASN1InputStream(admissions.toASN1Primitive().getEncoded());

			ASN1Sequence info = (ASN1Sequence)aIn.readObject();

			admissions = Admissions.getInstance(info);

			checkValues(admissions, name, auth);
		}

		private void checkValues(Admissions admissions, GeneralName name, NamingAuthority auth)
		{
			checkMandatoryField("admissionAuthority", name, admissions.getAdmissionAuthority());
			checkMandatoryField("namingAuthority", auth, admissions.getNamingAuthority());
		}

		public static void Main(string[] args)
		{
			runTest(new AdmissionsUnitTest());
		}
	}

}