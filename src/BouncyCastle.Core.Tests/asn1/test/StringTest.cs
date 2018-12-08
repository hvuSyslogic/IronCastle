namespace org.bouncycastle.asn1.test
{

	using Strings = org.bouncycastle.util.Strings;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// X.690 test example
	/// </summary>
	public class StringTest : SimpleTest
	{
		public override string getName()
		{
			return "String";
		}

		public override void performTest()
		{
			DERBitString bs = new DERBitString(new byte[] {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, unchecked((byte)0x89), unchecked((byte)0xab), unchecked((byte)0xcd), unchecked((byte)0xef)});

			if (!bs.getString().Equals("#0309000123456789ABCDEF"))
			{
				fail("DERBitString.getString() result incorrect");
			}

			if (!bs.ToString().Equals("#0309000123456789ABCDEF"))
			{
				fail("DERBitString.toString() result incorrect");
			}

			bs = new DERBitString(new byte[] {unchecked((byte)0xfe), unchecked((byte)0xdc), unchecked((byte)0xba), unchecked((byte)0x98), (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10});

			if (!bs.getString().Equals("#030900FEDCBA9876543210"))
			{
				fail("DERBitString.getString() result incorrect");
			}

			if (!bs.ToString().Equals("#030900FEDCBA9876543210"))
			{
				fail("DERBitString.toString() result incorrect");
			}

			DERUniversalString us = new DERUniversalString(new byte[] {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, unchecked((byte)0x89), unchecked((byte)0xab), unchecked((byte)0xcd), unchecked((byte)0xef)});

			if (!us.getString().Equals("#1C080123456789ABCDEF"))
			{
				fail("DERUniversalString.getString() result incorrect");
			}

			if (!us.ToString().Equals("#1C080123456789ABCDEF"))
			{
				fail("DERUniversalString.toString() result incorrect");
			}

			us = new DERUniversalString(new byte[] {unchecked((byte)0xfe), unchecked((byte)0xdc), unchecked((byte)0xba), unchecked((byte)0x98), (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10});

			if (!us.getString().Equals("#1C08FEDCBA9876543210"))
			{
				fail("DERUniversalString.getString() result incorrect");
			}

			if (!us.ToString().Equals("#1C08FEDCBA9876543210"))
			{
				fail("DERUniversalString.toString() result incorrect");
			}

			byte[] t61Bytes = new byte[] {(byte)-1, (byte)-2, (byte)-3, (byte)-4, (byte)-5, (byte)-6, (byte)-7, (byte)-8};
			string t61String = StringHelper.NewString(t61Bytes, "iso-8859-1");
			DERT61String t61 = new DERT61String(Strings.fromByteArray(t61Bytes));

			if (!t61.getString().Equals(t61String))
			{
				fail("DERT61String.getString() result incorrect");
			}

			if (!t61.ToString().Equals(t61String))
			{
				fail("DERT61String.toString() result incorrect");
			}

			char[] shortChars = new char[] {'a', 'b', 'c', 'd', 'e'};
			char[] longChars = new char[1000];

			for (int i = 0; i != longChars.Length; i++)
			{
				longChars[i] = 'X';
			}

			checkString(new DERBMPString(new string(shortChars)), new DERBMPString(new string(longChars)));
			checkString(new DERUTF8String(new string(shortChars)), new DERUTF8String(new string(longChars)));
			checkString(new DERIA5String(new string(shortChars)), new DERIA5String(new string(longChars)));
			checkString(new DERPrintableString(new string(shortChars)), new DERPrintableString(new string(longChars)));
			checkString(new DERVisibleString(new string(shortChars)), new DERVisibleString(new string(longChars)));
			checkString(new DERGeneralString(new string(shortChars)), new DERGeneralString(new string(longChars)));
			checkString(new DERT61String(new string(shortChars)), new DERT61String(new string(longChars)));

			shortChars = new char[] {'1', '2', '3', '4', '5'};
			longChars = new char[1000];

			for (int i = 0; i != longChars.Length; i++)
			{
				longChars[i] = '1';
			}

			checkString(new DERNumericString(new string(shortChars)), new DERNumericString(new string(longChars)));

			byte[] shortBytes = new byte[] {(byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e'};
			byte[] longBytes = new byte[1000];

			for (int i = 0; i != longChars.Length; i++)
			{
				longBytes[i] = (byte)'X';
			}

			checkString(new DERUniversalString(shortBytes), new DERUniversalString(longBytes));

		}

		private void checkString(ASN1String shortString, ASN1String longString)
		{
			ASN1String short2 = (ASN1String)ASN1Primitive.fromByteArray(((ASN1Primitive)shortString).getEncoded());

			if (!shortString.ToString().Equals(short2.ToString()))
			{
				fail(short2.GetType().getName() + " shortBytes result incorrect");
			}

			ASN1String long2 = (ASN1String)ASN1Primitive.fromByteArray(((ASN1Primitive)longString).getEncoded());

			if (!longString.ToString().Equals(long2.ToString()))
			{
				fail(long2.GetType().getName() + " longBytes result incorrect");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new StringTest());
		}
	}

}