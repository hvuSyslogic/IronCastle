namespace org.bouncycastle.asn1.test
{
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Set sorting test example
	/// </summary>
	public class SetTest : SimpleTest
	{

		public override string getName()
		{
			return "Set";
		}

		private void checkedSortedSet(int attempt, ASN1Set s)
		{
			if (s.getObjectAt(0) is ASN1Boolean && s.getObjectAt(1) is ASN1Integer && s.getObjectAt(2) is DERBitString && s.getObjectAt(3) is DEROctetString)
			{
				return;
			}

			fail("sorting failed on attempt: " + attempt);
		}

		public override void performTest()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			byte[] data = new byte[10];

			v.add(new DEROctetString(data));
			v.add(new DERBitString(data));
			v.add(new ASN1Integer(100));
			v.add(ASN1Boolean.getInstance(true));

			checkedSortedSet(0, new DERSet(v));

			v = new ASN1EncodableVector();
			v.add(new ASN1Integer(100));
			v.add(ASN1Boolean.getInstance(true));
			v.add(new DEROctetString(data));
			v.add(new DERBitString(data));

			checkedSortedSet(1, new DERSet(v));

			v = new ASN1EncodableVector();
			v.add(ASN1Boolean.getInstance(true));
			v.add(new DEROctetString(data));
			v.add(new DERBitString(data));
			v.add(new ASN1Integer(100));


			checkedSortedSet(2, new DERSet(v));

			v = new ASN1EncodableVector();
			v.add(new DERBitString(data));
			v.add(new DEROctetString(data));
			v.add(new ASN1Integer(100));
			v.add(ASN1Boolean.getInstance(true));

			checkedSortedSet(3, new DERSet(v));

			v = new ASN1EncodableVector();
			v.add(new DEROctetString(data));
			v.add(new DERBitString(data));
			v.add(new ASN1Integer(100));
			v.add(ASN1Boolean.getInstance(true));

			ASN1Set s = new BERSet(v);

			if (!(s.getObjectAt(0) is DEROctetString))
			{
				fail("BER set sort order changed.");
			}

			// create an implicitly tagged "set" without sorting
			ASN1TaggedObject tag = new DERTaggedObject(false, 1, new DERSequence(v));
			s = ASN1Set.getInstance(tag, false);

			if (s.getObjectAt(0) is ASN1Boolean)
			{
				fail("sorted when shouldn't be.");
			}

			// equality test
			v = new ASN1EncodableVector();

			v.add(ASN1Boolean.getInstance(true));
			v.add(ASN1Boolean.getInstance(true));
			v.add(ASN1Boolean.getInstance(true));

			s = new DERSet(v);
		}

		public static void Main(string[] args)
		{
			runTest(new SetTest());
		}
	}

}