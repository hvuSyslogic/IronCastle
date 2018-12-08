using System;

namespace org.bouncycastle.asn1.test
{

	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class EqualsAndHashCodeTest : Test
	{
		public virtual TestResult perform()
		{
			byte[] data = new byte[] {0, 1, 0, 1, 0, 0, 1};

			ASN1Primitive[] values = new ASN1Primitive[]
			{
				new BERConstructedOctetString(data),
				new BERSequence(new DERPrintableString("hello world")),
				new BERSet(new DERPrintableString("hello world")),
				new BERTaggedObject(0, new DERPrintableString("hello world")),
				new DERApplicationSpecific(0, data),
				new DERBitString(data),
				new DERBMPString("hello world"),
				new ASN1Boolean(true),
				new ASN1Boolean(false),
				new ASN1Enumerated(100),
				new DERGeneralizedTime("20070315173729Z"),
				new DERGeneralString("hello world"),
				new DERIA5String("hello"),
				new ASN1Integer(1000),
				new DERNull(),
				new DERNumericString("123456"),
				new ASN1ObjectIdentifier("1.1.1.10000.1"),
				new DEROctetString(data),
				new DERPrintableString("hello world"),
				new DERSequence(new DERPrintableString("hello world")),
				new DERSet(new DERPrintableString("hello world")),
				new DERT61String("hello world"),
				new DERTaggedObject(0, new DERPrintableString("hello world")),
				new DERUniversalString(data),
				new DERUTCTime(DateTime.Now),
				new DERUTF8String("hello world"),
				new DERVisibleString("hello world"),
				new DERGraphicString(Hex.decode("deadbeef")),
				new DERVideotexString(Strings.toByteArray("Hello World"))
			};

			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				ASN1OutputStream aOut = new ASN1OutputStream(bOut);

				for (int i = 0; i != values.Length; i++)
				{
					aOut.writeObject(values[i]);
				}

				ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
				ASN1InputStream aIn = new ASN1InputStream(bIn);

				for (int i = 0; i != values.Length; i++)
				{
					ASN1Primitive o = aIn.readObject();
					if (!o.Equals(values[i]))
					{
						return new SimpleTestResult(false, getName() + ": Failed equality test for " + o.GetType());
					}

					if (o.GetHashCode() != values[i].GetHashCode())
					{
						return new SimpleTestResult(false, getName() + ": Failed hashCode test for " + o.GetType());
					}
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": Failed - exception " + e.ToString(), e);
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual string getName()
		{
			return "EqualsAndHashCode";
		}

		public static void Main(string[] args)
		{
			EqualsAndHashCodeTest test = new EqualsAndHashCodeTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}