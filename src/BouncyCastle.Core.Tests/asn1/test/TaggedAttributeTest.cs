using org.bouncycastle.asn1.cmc;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CMCObjectIdentifiers = org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
	using TaggedAttribute = org.bouncycastle.asn1.cmc.TaggedAttribute;
	using Arrays = org.bouncycastle.util.Arrays;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class TaggedAttributeTest : SimpleTest
	{
		public override string getName()
		{
			return "TaggedAttributeTest";
		}

		public override void performTest()
		{
			//
			// This creates and tests the various get instance  methods.
			//
			TaggedAttribute ta = new TaggedAttribute(new BodyPartID(10L), CMCObjectIdentifiers_Fields.id_cct_PKIData, new DERSet(new DERIA5String("Cats")));

			byte[] d = ta.getEncoded();

			{
				TaggedAttribute res1 = TaggedAttribute.getInstance(d);
				isEquals(ta.getBodyPartID(), res1.getBodyPartID());
				isEquals(ta.getAttrType(), res1.getAttrType());
				isEquals(ta.getAttrValues().getObjectAt(0), res1.getAttrValues().getObjectAt(0));
				isTrue(Arrays.areEqual(res1.getEncoded(), d));
			}

			//
			// Where sequence is too short.
			//
			try
			{
				ASN1Sequence seq = new DERSequence(new ASN1Encodable[] {new BodyPartID(10)});

				TaggedAttribute.getInstance(seq);
				fail("no exception");
			}
			catch (IllegalArgumentException e)
			{
				isEquals("incorrect sequence size", e.getMessage());
			}

			//
			// Where sequence is too long.
			//
			try
			{
				ASN1Sequence seq = new DERSequence(new ASN1Encodable[] {ta.getBodyPartID(), ta.getAttrType(), ta.getAttrValues(), new ASN1Integer(0)});

				TaggedAttribute.getInstance(seq);
				fail("no exception");
			}
			catch (IllegalArgumentException e)
			{
				isEquals("incorrect sequence size", e.getMessage());
			}
		}

		public static void Main(string[] args)
		{
			runTest(new TaggedAttributeTest());
		}
	}

}