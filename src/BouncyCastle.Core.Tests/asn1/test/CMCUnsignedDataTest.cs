using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using BodyPartPath = org.bouncycastle.asn1.cmc.BodyPartPath;
	using CMCUnsignedData = org.bouncycastle.asn1.cmc.CMCUnsignedData;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class CMCUnsignedDataTest : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new CMCUnsignedDataTest());
		}

		public override string getName()
		{
			return "CMCUnsignedDataTest";
		}

		public override void performTest()
		{
			// Encode then decode
			CMCUnsignedData data = new CMCUnsignedData(new BodyPartPath(new BodyPartID(10L)), PKCSObjectIdentifiers_Fields.certBag, new DEROctetString("Cats".GetBytes()));
			byte[] b = data.getEncoded();
			CMCUnsignedData result = CMCUnsignedData.getInstance(data);

			isEquals(data.getBodyPartPath(), result.getBodyPartPath());
			isEquals(data.getIdentifier(), result.getIdentifier());
			isEquals(data.getContent(), result.getContent());

			// Sequence length must be 3

			try
			{
				CMCUnsignedData.getInstance(new DERSequence(new ASN1Integer(10)));
				fail("Must fail, sequence must be 3");
			}
			catch (Exception ex)
			{
				isEquals(ex.GetType(), typeof(IllegalArgumentException));
			}

			try
			{
				CMCUnsignedData.getInstance(new DERSequence(new ASN1Encodable[]
				{
					new ASN1Integer(10),
					new ASN1Integer(10),
					new ASN1Integer(10),
					new ASN1Integer(10)
				}));
				fail("Must fail, sequence must be 3");
			}
			catch (Exception ex)
			{
				isEquals(ex.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}