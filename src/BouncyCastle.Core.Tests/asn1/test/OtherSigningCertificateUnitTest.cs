namespace org.bouncycastle.asn1.test
{

	using OtherCertID = org.bouncycastle.asn1.ess.OtherCertID;
	using OtherSigningCertificate = org.bouncycastle.asn1.ess.OtherSigningCertificate;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class OtherSigningCertificateUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "OtherSigningCertificate";
		}

		public override void performTest()
		{
			AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.2.3"));
			byte[] digest = new byte[20];
			OtherCertID otherCertID = new OtherCertID(algId, digest);

			OtherSigningCertificate otherCert = new OtherSigningCertificate(otherCertID);

			checkConstruction(otherCert, otherCertID);

			otherCert = OtherSigningCertificate.getInstance(null);

			if (otherCert != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				OtherCertID.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(OtherSigningCertificate otherCert, OtherCertID otherCertID)
		{
			checkValues(otherCert, otherCertID);

			otherCert = OtherSigningCertificate.getInstance(otherCert);

			checkValues(otherCert, otherCertID);

			ASN1InputStream aIn = new ASN1InputStream(otherCert.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			otherCert = OtherSigningCertificate.getInstance(seq);

			checkValues(otherCert, otherCertID);
		}

		private void checkValues(OtherSigningCertificate otherCert, OtherCertID otherCertID)
		{
			if (otherCert.getCerts().Length != 1)
			{
				fail("getCerts() length wrong");
			}
			checkMandatoryField("getCerts()[0]", otherCertID, otherCert.getCerts()[0]);
		}

		public static void Main(string[] args)
		{
			runTest(new OtherSigningCertificateUnitTest());
		}
	}

}