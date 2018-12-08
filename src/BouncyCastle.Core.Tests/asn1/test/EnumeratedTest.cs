namespace org.bouncycastle.asn1.test
{

	using TestCase = junit.framework.TestCase;

	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Tests used to verify correct decoding of the ENUMERATED type.
	/// </summary>
	public class EnumeratedTest : TestCase
	{
		/// <summary>
		/// Test vector used to test decoding of multiple items. This sample uses an ENUMERATED and a BOOLEAN.
		/// </summary>
		private static readonly byte[] MultipleSingleByteItems = Hex.decode("30060a01010101ff");

		/// <summary>
		/// Test vector used to test decoding of multiple items. This sample uses two ENUMERATEDs.
		/// </summary>
		private static readonly byte[] MultipleDoubleByteItems = Hex.decode("30080a0201010a020202");

		/// <summary>
		/// Test vector used to test decoding of multiple items. This sample uses an ENUMERATED and an OBJECT IDENTIFIER.
		/// </summary>
		private static readonly byte[] MultipleTripleByteItems = Hex.decode("300a0a0301010106032b0601");

		/// <summary>
		/// Makes sure multiple identically sized values are parsed correctly.
		/// </summary>
		public virtual void testReadingMultipleSingleByteItems()
		{
			ASN1Primitive obj = ASN1Primitive.fromByteArray(MultipleSingleByteItems);

			assertTrue("Null ASN.1 SEQUENCE", obj is ASN1Sequence);

			ASN1Sequence sequence = (ASN1Sequence)obj;

			assertEquals("2 items expected", 2, sequence.size());

			ASN1Enumerated enumerated = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

			assertNotNull("ENUMERATED expected", enumerated);

			assertEquals("Unexpected ENUMERATED value", 1, enumerated.getValue().intValue());

			ASN1Boolean b = ASN1Boolean.getInstance(sequence.getObjectAt(1));

			assertNotNull("BOOLEAN expected", b);

			assertTrue("Unexpected BOOLEAN value", b.isTrue());
		}

		/// <summary>
		/// Makes sure multiple identically sized values are parsed correctly.
		/// </summary>
		public virtual void testReadingMultipleDoubleByteItems()
		{
			ASN1Primitive obj = ASN1Primitive.fromByteArray(MultipleDoubleByteItems);

			assertTrue("Null ASN.1 SEQUENCE", obj is ASN1Sequence);

			ASN1Sequence sequence = (ASN1Sequence)obj;

			assertEquals("2 items expected", 2, sequence.size());

			ASN1Enumerated enumerated1 = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

			assertNotNull("ENUMERATED expected", enumerated1);

			assertEquals("Unexpected ENUMERATED value", 257, enumerated1.getValue().intValue());

			ASN1Enumerated enumerated2 = ASN1Enumerated.getInstance(sequence.getObjectAt(1));

			assertNotNull("ENUMERATED expected", enumerated2);

			assertEquals("Unexpected ENUMERATED value", 514, enumerated2.getValue().intValue());
		}

		/// <summary>
		/// Makes sure multiple identically sized values are parsed correctly.
		/// </summary>
		public virtual void testReadingMultipleTripleByteItems()
		{
			ASN1Primitive obj = ASN1Primitive.fromByteArray(MultipleTripleByteItems);

			assertTrue("Null ASN.1 SEQUENCE", obj is ASN1Sequence);

			ASN1Sequence sequence = (ASN1Sequence)obj;

			assertEquals("2 items expected", 2, sequence.size());

			ASN1Enumerated enumerated = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

			assertNotNull("ENUMERATED expected", enumerated);

			assertEquals("Unexpected ENUMERATED value", 65793, enumerated.getValue().intValue());

			ASN1ObjectIdentifier objectId = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(1));

			assertNotNull("OBJECT IDENTIFIER expected", objectId);

			assertEquals("Unexpected OBJECT IDENTIFIER value", "1.3.6.1", objectId.getId());
		}
	}

}