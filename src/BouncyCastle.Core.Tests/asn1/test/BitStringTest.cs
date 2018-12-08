using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.test
{

	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class BitStringTest : SimpleTest
	{
		private void testZeroLengthStrings()
		{
			// basic construction
			DERBitString s1 = new DERBitString(new byte[0], 0);

			// check getBytes()
			s1.getBytes();

			// check encoding/decoding
			DERBitString derBit = (DERBitString)ASN1Primitive.fromByteArray(s1.getEncoded());

			if (!Arrays.areEqual(s1.getEncoded(), Hex.decode("030100")))
			{
				fail("zero encoding wrong");
			}

			try
			{
				new DERBitString(null, 1);
				fail("exception not thrown");
			}
			catch (NullPointerException e)
			{
				if (!"data cannot be null".Equals(e.getMessage()))
				{
					fail("Unexpected exception");
				}
			}

			try
			{
				new DERBitString(new byte[0], 1);
				fail("exception not thrown");
			}
			catch (IllegalArgumentException e)
			{
				if (!"zero length data with non-zero pad bits".Equals(e.getMessage()))
				{
					fail("Unexpected exception");
				}
			}

			try
			{
				new DERBitString(new byte[1], 8);
				fail("exception not thrown");
			}
			catch (IllegalArgumentException e)
			{
				if (!"pad bits cannot be greater than 7 or less than 0".Equals(e.getMessage()))
				{
					fail("Unexpected exception");
				}
			}

			DERBitString s2 = new DERBitString(0);
			if (!Arrays.areEqual(s1.getEncoded(), s2.getEncoded()))
			{
				fail("zero encoding wrong");
			}
		}

		private void testRandomPadBits()
		{
			byte[] test = Hex.decode("030206c0");

			byte[] test1 = Hex.decode("030206f0");
			byte[] test2 = Hex.decode("030206c1");
			byte[] test3 = Hex.decode("030206c7");
			byte[] test4 = Hex.decode("030206d1");

			encodingCheck(test, test1);
			encodingCheck(test, test2);
			encodingCheck(test, test3);
			encodingCheck(test, test4);
		}

		private void encodingCheck(byte[] derData, byte[] dlData)
		{
			if (Arrays.areEqual(derData, ASN1Primitive.fromByteArray(dlData).getEncoded()))
			{
				fail("failed DL check");
			}
			ASN1BitString dl = DLBitString.getInstance(dlData);

			isTrue("DL test failed", dl is DLBitString);
			if (!Arrays.areEqual(derData, ASN1Primitive.fromByteArray(dlData).getEncoded(ASN1Encoding_Fields.DER)))
			{
				fail("failed DER check");
			}
			try
			{
				DERBitString.getInstance(dlData);
				fail("no exception");
			}
			catch (IllegalArgumentException)
			{
				// ignore
			}
			ASN1BitString der = DERBitString.getInstance(derData);
			isTrue("DER test failed", der is DERBitString);
		}

		public override void performTest()
		{
			KeyUsage k = new KeyUsage(KeyUsage.digitalSignature);
			if ((k.getBytes()[0] != (byte)KeyUsage.digitalSignature) || (k.getPadBits() != 7))
			{
				fail("failed digitalSignature");
			}

			k = new KeyUsage(KeyUsage.nonRepudiation);
			if ((k.getBytes()[0] != (byte)KeyUsage.nonRepudiation) || (k.getPadBits() != 6))
			{
				fail("failed nonRepudiation");
			}

			k = new KeyUsage(KeyUsage.keyEncipherment);
			if ((k.getBytes()[0] != (byte)KeyUsage.keyEncipherment) || (k.getPadBits() != 5))
			{
				fail("failed keyEncipherment");
			}

			k = new KeyUsage(KeyUsage.cRLSign);
			if ((k.getBytes()[0] != (byte)KeyUsage.cRLSign) || (k.getPadBits() != 1))
			{
				fail("failed cRLSign");
			}

			k = new KeyUsage(KeyUsage.decipherOnly);
			if ((k.getBytes()[1] != (byte)(KeyUsage.decipherOnly >> 8)) || (k.getPadBits() != 7))
			{
				fail("failed decipherOnly");
			}

			// test for zero length bit string
			try
			{
				ASN1Primitive.fromByteArray((new DERBitString(new byte[0], 0)).getEncoded());
			}
			catch (IOException e)
			{
				fail(e.ToString());
			}

			testRandomPadBits();
			testZeroLengthStrings();
		}

		public override string getName()
		{
			return "BitString";
		}

		public static void Main(string[] args)
		{
			BitStringTest test = new BitStringTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}