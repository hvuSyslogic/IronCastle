using System;

namespace org.bouncycastle.asn1.test
{

	using RecipientKeyIdentifier = org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
	using SMIMECapabilitiesAttribute = org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
	using SMIMECapability = org.bouncycastle.asn1.smime.SMIMECapability;
	using SMIMECapabilityVector = org.bouncycastle.asn1.smime.SMIMECapabilityVector;
	using SMIMEEncryptionKeyPreferenceAttribute = org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class SMIMETest : Test
	{
		internal byte[] attrBytes = Base64.decode("MDQGCSqGSIb3DQEJDzEnMCUwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMAcGBSsOAwIH");
		internal byte[] prefBytes = Base64.decode("MCwGCyqGSIb3DQEJEAILMR2hGwQIAAAAAAAAAAAYDzIwMDcwMzE1MTczNzI5Wg==");

		private bool isSameAs(byte[] a, byte[] b)
		{
			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public virtual TestResult perform()
		{
			SMIMECapabilityVector caps = new SMIMECapabilityVector();

			caps.addCapability(SMIMECapability.dES_EDE3_CBC);
			caps.addCapability(SMIMECapability.rC2_CBC, 128);
			caps.addCapability(SMIMECapability.dES_CBC);

			SMIMECapabilitiesAttribute attr = new SMIMECapabilitiesAttribute(caps);

			SMIMEEncryptionKeyPreferenceAttribute pref = new SMIMEEncryptionKeyPreferenceAttribute(new RecipientKeyIdentifier(new DEROctetString(new byte[8]), new DERGeneralizedTime("20070315173729Z"), null));

			try
			{
				if (!isSameAs(attr.getEncoded(), attrBytes))
				{
					return new SimpleTestResult(false, getName() + ": Failed attr data check");
				}

				ByteArrayInputStream bIn = new ByteArrayInputStream(attrBytes);
				ASN1InputStream aIn = new ASN1InputStream(bIn);

				ASN1Primitive o = aIn.readObject();
				if (!attr.Equals(o))
				{
					return new SimpleTestResult(false, getName() + ": Failed equality test for attr");
				}

				if (!isSameAs(pref.getEncoded(), prefBytes))
				{
					return new SimpleTestResult(false, getName() + ": Failed attr data check");
				}

				bIn = new ByteArrayInputStream(prefBytes);
				aIn = new ASN1InputStream(bIn);

				o = aIn.readObject();
				if (!pref.Equals(o))
				{
					return new SimpleTestResult(false, getName() + ": Failed equality test for pref");
				}

				return new SimpleTestResult(true, getName() + ": Okay");
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": Failed - exception " + e.ToString(), e);
			}
		}

		public virtual string getName()
		{
			return "SMIME";
		}

		public static void Main(string[] args)
		{
			SMIMETest test = new SMIMETest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}