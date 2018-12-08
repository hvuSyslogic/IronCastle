using System;

namespace org.bouncycastle.asn1.test
{

	using GetCRL = org.bouncycastle.asn1.cmc.GetCRL;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X500NameBuilder = org.bouncycastle.asn1.x500.X500NameBuilder;
	using BCStyle = org.bouncycastle.asn1.x500.style.BCStyle;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using ReasonFlags = org.bouncycastle.asn1.x509.ReasonFlags;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class GetCRLTest : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new GetCRLTest());
		}

		public override string getName()
		{
			return "GetCRLTest";
		}

		public override void performTest()
		{

			{
				X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
				builder.addRDN(BCStyle.C, "AU");
				X500Name name = new X500Name(builder.build().ToString());

				GetCRL crl = new GetCRL(name, new GeneralName(GeneralName.rfc822Name, "/"), new ASN1GeneralizedTime(DateTime.Now), new ReasonFlags(ReasonFlags.affiliationChanged)
			   );

				byte[] b = crl.getEncoded();

				GetCRL crlResp = GetCRL.getInstance(b);

				isEquals("IssuerName", crl.getIssuerName(), crlResp.getIssuerName());
				isEquals("cRLName", crl.getcRLName(), crlResp.getcRLName());
				isEquals("time", crl.getTime(), crlResp.getTime());
				isEquals("reasons", crl.getReasons(), crlResp.getReasons());

				try
				{
					GetCRL.getInstance(new DERSequence(new ASN1Encodable[0]));
					fail("Must not accept sequence less than 1");
				}
				catch (Exception t)
				{
					isEquals("", t.GetType(), typeof(IllegalArgumentException));
				}

				try
				{
					GetCRL.getInstance(new DERSequence(new ASN1Encodable[5]));
					fail("Must not accept sequence larger than 5");
				}
				catch (Exception t)
				{
					isEquals("", t.GetType(), typeof(IllegalArgumentException));
				}
			}

			{ // Permutate on options test all possible combinations.

				X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
				builder.addRDN(BCStyle.C, "AU");
				X500Name name = new X500Name(builder.build().ToString());
				GeneralName generalName = null;
				ASN1GeneralizedTime generalizedTime = null;
				ReasonFlags flags = null;

				for (int t = 0; t < 8; t++)
				{
					if ((t & 1) == 1)
					{
						generalName = new GeneralName(GeneralName.rfc822Name, "/");
					}
					if ((t & 2) == 2)
					{
						generalizedTime = new ASN1GeneralizedTime(DateTime.Now);
					}

					if ((t & 4) == 4)
					{
						flags = new ReasonFlags(ReasonFlags.affiliationChanged);
					}


					GetCRL crl = new GetCRL(name, generalName, generalizedTime, flags);

					byte[] b = crl.getEncoded();

					GetCRL crlResp = GetCRL.getInstance(b);

					isEquals("IssuerName", crl.getIssuerName(), crlResp.getIssuerName());
					isEquals("cRLName", crl.getcRLName(), crlResp.getcRLName());
					isEquals("time", crl.getTime(), crlResp.getTime());
					isEquals("reasons", crl.getReasons(), crlResp.getReasons());

				}
			}

		}
	}

}