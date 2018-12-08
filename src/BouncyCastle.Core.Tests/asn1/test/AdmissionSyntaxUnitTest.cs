namespace org.bouncycastle.asn1.test
{

	using AdmissionSyntax = org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
	using Admissions = org.bouncycastle.asn1.isismtt.x509.Admissions;
	using NamingAuthority = org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
	using ProfessionInfo = org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class AdmissionSyntaxUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "AdmissionSyntax";
		}

		public override void performTest()
		{
			GeneralName name = new GeneralName(new X500Name("CN=hello world"));
			ASN1Sequence admissions = new DERSequence(new Admissions(name, new NamingAuthority(new ASN1ObjectIdentifier("1.2.3"), "url", new DirectoryString("fred")), new ProfessionInfo[0]));
			AdmissionSyntax syntax = new AdmissionSyntax(name, admissions);

			checkConstruction(syntax, name, admissions);

			syntax = AdmissionSyntax.getInstance(null);

			if (syntax != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				AdmissionSyntax.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(AdmissionSyntax syntax, GeneralName authority, ASN1Sequence admissions)
		{
			checkValues(syntax, authority, admissions);

			syntax = AdmissionSyntax.getInstance(syntax);

			checkValues(syntax, authority, admissions);

			ASN1InputStream aIn = new ASN1InputStream(syntax.toASN1Primitive().getEncoded());

			ASN1Sequence info = (ASN1Sequence)aIn.readObject();

			syntax = AdmissionSyntax.getInstance(info);

			checkValues(syntax, authority, admissions);
		}

		private void checkValues(AdmissionSyntax syntax, GeneralName authority, ASN1Sequence admissions)
		{
			checkMandatoryField("admissionAuthority", authority, syntax.getAdmissionAuthority());

			Admissions[] adm = syntax.getContentsOfAdmissions();

			if (adm.Length != 1 || !adm[0].Equals(admissions.getObjectAt(0)))
			{
				fail("admissions check failed");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new AdmissionSyntaxUnitTest());
		}
	}

}