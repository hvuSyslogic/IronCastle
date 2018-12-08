using System;

namespace org.bouncycastle.asn1.test
{
	using ExtendedFailInfo = org.bouncycastle.asn1.cmc.ExtendedFailInfo;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class ExtendedFailInfoTest : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new ExtendedFailInfoTest());
		}

		public override string getName()
		{
			return "ExtendedFailInfo";
		}

		public override void performTest()
		{
			// OID not real
			ExtendedFailInfo extendedFailInfo = new ExtendedFailInfo(new ASN1ObjectIdentifier("1.2.3.2"), new ASN1Integer(10L));
			byte[] b = extendedFailInfo.getEncoded();
			ExtendedFailInfo extendedFailInfoResult = ExtendedFailInfo.getInstance(b);

			isEquals("failInfoOID", extendedFailInfo.getFailInfoOID(), extendedFailInfoResult.getFailInfoOID());
			isEquals("failInfoValue", extendedFailInfo.getFailInfoValue(), extendedFailInfoResult.getFailInfoValue());

			try
			{
				ExtendedFailInfo.getInstance(new DERSequence(new ASN1Integer(10L)));
				fail("Sequence must be 2 elements.");
			}
			catch (Exception t)
			{
				isEquals("Wrong exception type",t.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}