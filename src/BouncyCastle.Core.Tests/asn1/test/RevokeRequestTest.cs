using System;

namespace org.bouncycastle.asn1.test
{

	using RevokeRequest = org.bouncycastle.asn1.cmc.RevokeRequest;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X500NameBuilder = org.bouncycastle.asn1.x500.X500NameBuilder;
	using BCStyle = org.bouncycastle.asn1.x500.style.BCStyle;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Pack = org.bouncycastle.util.Pack;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class RevokeRequestTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new RevokeRequestTest());
		}

		public override string getName()
		{
			return "RevokeRequestTest";
		}

		public override void performTest()
		{


			X500NameBuilder builder = new X500NameBuilder();
			builder.addRDN(BCStyle.OU, "Bouncycastle");

			X500Name name = builder.build();

			for (int t = 0; t < 8; t++)
			{
				ASN1GeneralizedTime invalidityDate = null;
				ASN1OctetString passphrase = null;
				DERUTF8String comment = null;

				if ((t & 1) == 1)
				{
					invalidityDate = new ASN1GeneralizedTime(DateTime.Now);
				}
				if ((t & 2) == 2)
				{
					passphrase = new DEROctetString(Pack.longToBigEndian(System.currentTimeMillis()));
				}
				if ((t & 4) == 4)
				{
					comment = new DERUTF8String("T" + Long.toOctalString(System.currentTimeMillis()));
				}

				RevokeRequest rr = new RevokeRequest(name, new ASN1Integer(12L), CRLReason.getInstance(new ASN1Enumerated(CRLReason.certificateHold)), invalidityDate, passphrase, comment);
				byte[] b = rr.getEncoded();
				RevokeRequest rrResp = RevokeRequest.getInstance(b);

				isEquals("issuerName", rr.getName(), rrResp.getName());
				isEquals("serialNumber", rr.getSerialNumber(), rrResp.getSerialNumber());
				isEquals("reason", rr.getReason(), rrResp.getReason());
				isEquals("invalidityDate", rr.getInvalidityDate(), rrResp.getInvalidityDate());
				isTrue("passphrase", areEqual(rr.getPassPhrase(), rrResp.getPassPhrase()));
				isEquals("comment", rr.getComment(), rrResp.getComment());

			}

			try
			{
				RevokeRequest.getInstance(new DERSequence());
				fail("Sequence is less that 3");
			}
			catch (Exception t)
			{
				isEquals("Exception type", t.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}