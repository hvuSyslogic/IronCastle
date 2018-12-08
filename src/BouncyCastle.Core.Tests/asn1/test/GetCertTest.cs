using System;

namespace org.bouncycastle.asn1.test
{

	using GetCert = org.bouncycastle.asn1.cmc.GetCert;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class GetCertTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new GetCertTest());
		}

		public override string getName()
		{
			return "GetCertTest";
		}

		public override void performTest()
		{
			GetCert gs = new GetCert(new GeneralName(GeneralName.dNSName,"fish"),new BigInteger("109"));
			byte[] b = gs.getEncoded();
			GetCert gsResp = GetCert.getInstance(b);

			isEquals("Issuer Name",gs.getIssuerName(), gsResp.getIssuerName());
			isEquals("Serial Number",gs.getSerialNumber(), gsResp.getSerialNumber());

			try
			{
				GetCert.getInstance(new DERSequence(new ASN1Integer(1L)));
				fail("Sequence must be length of 2");
			}
			catch (Exception t)
			{
				isEquals("Wrong exception",t.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}