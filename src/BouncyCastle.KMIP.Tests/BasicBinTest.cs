using System;

namespace org.bouncycastle.kmip.test
{

	using TestCase = junit.framework.TestCase;
	using KMIPBigInteger = org.bouncycastle.kmip.wire.KMIPBigInteger;
	using KMIPBoolean = org.bouncycastle.kmip.wire.KMIPBoolean;
	using KMIPByteString = org.bouncycastle.kmip.wire.KMIPByteString;
	using KMIPDateTime = org.bouncycastle.kmip.wire.KMIPDateTime;
	using KMIPEncodable = org.bouncycastle.kmip.wire.KMIPEncodable;
	using KMIPEnumeration = org.bouncycastle.kmip.wire.KMIPEnumeration;
	using KMIPInteger = org.bouncycastle.kmip.wire.KMIPInteger;
	using KMIPInterval = org.bouncycastle.kmip.wire.KMIPInterval;
	using KMIPItem = org.bouncycastle.kmip.wire.KMIPItem;
	using KMIPLong = org.bouncycastle.kmip.wire.KMIPLong;
	using KMIPStructure = org.bouncycastle.kmip.wire.KMIPStructure;
	using KMIPTextString = org.bouncycastle.kmip.wire.KMIPTextString;
	using BinaryEncoder = org.bouncycastle.kmip.wire.binary.BinaryEncoder;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class BasicBinTest : TestCase
	{
		public virtual void testInteger()
		{
			KMIPInteger obj = new KMIPInteger(0x420020, 8);

			check(obj, Hex.decode("42002002000000040000000800000000"));
		}

		public virtual void testLong()
		{
			KMIPLong obj = new KMIPLong(0x420020, 123456789000000000L);

			check(obj, Hex.decode("420020030000000801b69b4ba5749200"));
		}

		public virtual void testBigInteger()
		{
			KMIPBigInteger obj = new KMIPBigInteger(0x420020, new BigInteger("1234567890000000000000000000"));

			check(obj, Hex.decode("42002004000000100000000003fd35eb6bc2df4618080000"));
		}

		public virtual void testEnumeration()
		{
			KMIPEnumeration obj = new KMIPEnumeration(0x420020, 255);

			check(obj, Hex.decode("4200200500000004000000ff00000000"));
		}

		public virtual void testBoolean()
		{
			KMIPBoolean obj = new KMIPBoolean(0x420020, true);

			check(obj, Hex.decode("42002006000000080000000000000001"));

			obj = new KMIPBoolean(0x420020, false);

			check(obj, Hex.decode("42002006000000080000000000000000"));
		}

		public virtual void testTextString()
		{
			KMIPTextString obj = new KMIPTextString(0x420020, "Hello World");

			check(obj, Hex.decode("420020070000000b48656c6c6f20576f726c640000000000"));
		}

		public virtual void testByteString()
		{
			KMIPByteString obj = new KMIPByteString(0x420020, new byte[] {0x01, 0x02, 0x3});

			check(obj, Hex.decode("42002008000000030102030000000000"));
		}

		public virtual void testDateTime()
		{
			KMIPDateTime obj = new KMIPDateTime(0x420020, new DateTime(0x47da67f8L));

			check(obj, Hex.decode("42002009000000080000000047da67f8"));
		}

		public virtual void testInterval()
		{
			KMIPInterval obj = new KMIPInterval(0x420020, 10 * 24 * 60 * 60);

			check(obj, Hex.decode("4200200a00000004000d2f0000000000"));
		}

		public virtual void testStructure()
		{
			KMIPStructure obj = new KMIPStructure(0x420020, new KMIPItem[]
			{
				new KMIPEnumeration(0x420004, 254),
				new KMIPInteger(0x420005, 255)
			});

			check(obj, Hex.decode("42002001000000204200040500000004000000FE000000004200050200000004000000FF00000000"));
		}

		private void check(KMIPEncodable obj, byte[] expected)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			BinaryEncoder bEnc = new BinaryEncoder(bOut);

			bEnc.output(obj);

			assertTrue(Arrays.areEqual(expected, bOut.toByteArray()));
		}
	}

}