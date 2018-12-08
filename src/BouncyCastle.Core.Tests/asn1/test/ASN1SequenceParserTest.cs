namespace org.bouncycastle.asn1.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class ASN1SequenceParserTest : TestCase
	{
		private static readonly byte[] seqData = Hex.decode("3006020100060129");
		private static readonly byte[] nestedSeqData = Hex.decode("300b0201000601293003020101");
		private static readonly byte[] expTagSeqData = Hex.decode("a1083006020100060129");
		private static readonly byte[] implTagSeqData = Hex.decode("a106020100060129");
		private static readonly byte[] nestedSeqExpTagData = Hex.decode("300d020100060129a1053003020101");
		private static readonly byte[] nestedSeqImpTagData = Hex.decode("300b020100060129a103020101");

		private static readonly byte[] berSeqData = Hex.decode("30800201000601290000");
		private static readonly byte[] berDERNestedSeqData = Hex.decode("308002010006012930030201010000");
		private static readonly byte[] berNestedSeqData = Hex.decode("3080020100060129308002010100000000");
		private static readonly byte[] berExpTagSeqData = Hex.decode("a180308002010006012900000000");

		private static readonly byte[] berSeqWithDERNullData = Hex.decode("308005000201000601290000");

		public virtual void testDERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   DERSequenceGenerator seqGen = new DERSequenceGenerator(bOut);

		   seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

		   seqGen.close();

		   assertTrue("basic DER writing test failed.", Arrays.Equals(seqData, bOut.toByteArray()));
		}

		public virtual void testNestedDERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);

		   seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

		   DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());

		   seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

		   seqGen2.close();

		   seqGen1.close();

		   assertTrue("nested DER writing test failed.", Arrays.Equals(nestedSeqData, bOut.toByteArray()));
		}

		public virtual void testDERExplicitTaggedSequenceWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   DERSequenceGenerator seqGen = new DERSequenceGenerator(bOut, 1, true);

		   seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

		   seqGen.close();

		   assertTrue("explicit tag writing test failed.", Arrays.Equals(expTagSeqData, bOut.toByteArray()));
		}

		public virtual void testDERImplicitTaggedSequenceWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   DERSequenceGenerator seqGen = new DERSequenceGenerator(bOut, 1, false);

		   seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

		   seqGen.close();

		   assertTrue("implicit tag writing test failed.", Arrays.Equals(implTagSeqData, bOut.toByteArray()));
		}

		public virtual void testNestedExplicitTagDERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);

		   seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

		   DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, true);

		   seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

		   seqGen2.close();

		   seqGen1.close();

		   assertTrue("nested explicit tagged DER writing test failed.", Arrays.Equals(nestedSeqExpTagData, bOut.toByteArray()));
		}

		public virtual void testNestedImplicitTagDERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);

		   seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

		   DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, false);

		   seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

		   seqGen2.close();

		   seqGen1.close();

		   assertTrue("nested implicit tagged DER writing test failed.", Arrays.Equals(nestedSeqImpTagData, bOut.toByteArray()));
		}

		public virtual void testBERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   BERSequenceGenerator seqGen = new BERSequenceGenerator(bOut);

		   seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

		   seqGen.close();

		   assertTrue("basic BER writing test failed.", Arrays.Equals(berSeqData, bOut.toByteArray()));
		}

		public virtual void testNestedBERDERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   BERSequenceGenerator seqGen1 = new BERSequenceGenerator(bOut);

		   seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

		   DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());

		   seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

		   seqGen2.close();

		   seqGen1.close();

		   assertTrue("nested BER/DER writing test failed.", Arrays.Equals(berDERNestedSeqData, bOut.toByteArray()));
		}

		public virtual void testNestedBERWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   BERSequenceGenerator seqGen1 = new BERSequenceGenerator(bOut);

		   seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));

		   BERSequenceGenerator seqGen2 = new BERSequenceGenerator(seqGen1.getRawOutputStream());

		   seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));

		   seqGen2.close();

		   seqGen1.close();

		   assertTrue("nested BER writing test failed.", Arrays.Equals(berNestedSeqData, bOut.toByteArray()));
		}

		public virtual void testDERReading()
		{
			ASN1StreamParser aIn = new ASN1StreamParser(seqData);

			ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
			object o;
			int count = 0;

			assertNotNull("null sequence returned", seq);

			while ((o = seq.readObject()) != null)
			{
				switch (count)
				{
				case 0:
					assertTrue(o is ASN1Integer);
					break;
				case 1:
					assertTrue(o is ASN1ObjectIdentifier);
					break;
				}
				count++;
			}

			assertEquals("wrong number of objects in sequence", 2, count);
		}

		private void testNestedReading(byte[] data)
		{
			ASN1StreamParser aIn = new ASN1StreamParser(data);

			ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
			object o;
			int count = 0;

			assertNotNull("null sequence returned", seq);

			while ((o = seq.readObject()) != null)
			{
				switch (count)
				{
				case 0:
					assertTrue(o is ASN1Integer);
					break;
				case 1:
					assertTrue(o is ASN1ObjectIdentifier);
					break;
				case 2:
					assertTrue(o is ASN1SequenceParser);

					ASN1SequenceParser s = (ASN1SequenceParser)o;

					// NB: Must exhaust the nested parser
					while (s.readObject() != null)
					{
						// Nothing
					}

					break;
				}
				count++;
			}

			assertEquals("wrong number of objects in sequence", 3, count);
		}

		public virtual void testNestedDERReading()
		{
			testNestedReading(nestedSeqData);
		}

		public virtual void testBERReading()
		{
			ASN1StreamParser aIn = new ASN1StreamParser(berSeqData);

			ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
			object o;
			int count = 0;

			assertNotNull("null sequence returned", seq);

			while ((o = seq.readObject()) != null)
			{
				switch (count)
				{
				case 0:
					assertTrue(o is ASN1Integer);
					break;
				case 1:
					assertTrue(o is ASN1ObjectIdentifier);
					break;
				}
				count++;
			}

			assertEquals("wrong number of objects in sequence", 2, count);
		}

		public virtual void testNestedBERDERReading()
		{
			testNestedReading(berDERNestedSeqData);
		}

		public virtual void testNestedBERReading()
		{
			testNestedReading(berNestedSeqData);
		}

		public virtual void testBERExplicitTaggedSequenceWriting()
		{
		   ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		   BERSequenceGenerator seqGen = new BERSequenceGenerator(bOut, 1, true);

		   seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));

		   seqGen.addObject(new ASN1ObjectIdentifier("1.1"));

		   seqGen.close();

		   assertTrue("explicit BER tag writing test failed.", Arrays.Equals(berExpTagSeqData, bOut.toByteArray()));
		}

		public virtual void testSequenceWithDERNullReading()
		{
			testParseWithNull(berSeqWithDERNullData);
		}

		private void testParseWithNull(byte[] data)
		{
			ASN1StreamParser aIn = new ASN1StreamParser(data);
			ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
			object o;
			int count = 0;

			assertNotNull("null sequence returned", seq);

			while ((o = seq.readObject()) != null)
			{
				switch (count)
				{
				case 0:
					assertTrue(o is ASN1Null);
					break;
				case 1:
					assertTrue(o is ASN1Integer);
					break;
				case 2:
					assertTrue(o is ASN1ObjectIdentifier);
					break;
				}
				count++;
			}

			assertEquals("wrong number of objects in sequence", 3, count);
		}

		public static Test suite()
		{
			return new TestSuite(typeof(ASN1SequenceParserTest));
		}
	}

}