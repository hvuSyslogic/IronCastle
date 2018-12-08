namespace org.bouncycastle.asn1.test
{

	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	/// <summary>
	/// X.690 test example
	/// </summary>
	public class TagTest : SimpleTest
	{
		internal byte[] longTagged = Base64.decode("ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz" + "A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF" + "kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE" + "RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY" + "GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV" + "FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka" + "lAg=");

		internal byte[] longAppSpecificTag = Hex.decode("5F610101");

		public override string getName()
		{
			return "Tag";
		}

		public override void performTest()
		{
			ASN1InputStream aIn = new ASN1InputStream(longTagged);

			ASN1ApplicationSpecific app = (ASN1ApplicationSpecific)aIn.readObject();

			aIn = new ASN1InputStream(app.getContents());

			app = (ASN1ApplicationSpecific)aIn.readObject();

			aIn = new ASN1InputStream(app.getContents());

			ASN1TaggedObject tagged = (ASN1TaggedObject)aIn.readObject();

			if (tagged.getTagNo() != 32)
			{
				fail("unexpected tag value found - not 32");
			}

			tagged = (ASN1TaggedObject)ASN1Primitive.fromByteArray(tagged.getEncoded());

			if (tagged.getTagNo() != 32)
			{
				fail("unexpected tag value found on recode - not 32");
			}

			tagged = (ASN1TaggedObject)aIn.readObject();

			if (tagged.getTagNo() != 33)
			{
				fail("unexpected tag value found - not 33");
			}

			tagged = (ASN1TaggedObject)ASN1Primitive.fromByteArray(tagged.getEncoded());

			if (tagged.getTagNo() != 33)
			{
				fail("unexpected tag value found on recode - not 33");
			}

			aIn = new ASN1InputStream(longAppSpecificTag);

			app = (ASN1ApplicationSpecific)aIn.readObject();

			if (app.getApplicationTag() != 97)
			{
				fail("incorrect tag number read");
			}

			app = (ASN1ApplicationSpecific)ASN1Primitive.fromByteArray(app.getEncoded());

			if (app.getApplicationTag() != 97)
			{
				fail("incorrect tag number read on recode");
			}

			SecureRandom sr = new SecureRandom();
			for (int i = 0; i < 100; ++i)
			{
				int testTag = (int)((uint)sr.nextInt() >> (1 + ((int)((uint)sr.nextInt() >> 1)) % 26));
				app = new DERApplicationSpecific(testTag, new byte[]{1});
				app = (ASN1ApplicationSpecific)ASN1Primitive.fromByteArray(app.getEncoded());

				if (app.getApplicationTag() != testTag)
				{
					fail("incorrect tag number read on recode (random test value: " + testTag + ")");
				}
			}
		}

		public static void Main(string[] args)
		{
			runTest(new TagTest());
		}
	}

}