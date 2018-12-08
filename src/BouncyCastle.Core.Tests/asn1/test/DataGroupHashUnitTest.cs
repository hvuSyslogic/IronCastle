using System;

namespace org.bouncycastle.asn1.test
{

	using DataGroupHash = org.bouncycastle.asn1.icao.DataGroupHash;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class DataGroupHashUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "DataGroupHash";
		}

		private byte[] generateHash()
		{
			Random rand = new Random();
			byte[] bytes = new byte[20];

			for (int i = 0; i != bytes.Length; i++)
			{
				bytes[i] = (byte)rand.nextInt();
			}

			return bytes;
		}

		public override void performTest()
		{
			int dataGroupNumber = 1;
			ASN1OctetString dataHash = new DEROctetString(generateHash());
			DataGroupHash dg = new DataGroupHash(dataGroupNumber, dataHash);

			checkConstruction(dg, dataGroupNumber, dataHash);

			try
			{
				DataGroupHash.getInstance(null);
			}
			catch (Exception)
			{
				fail("getInstance() failed to handle null.");
			}

			try
			{
				DataGroupHash.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(DataGroupHash dg, int dataGroupNumber, ASN1OctetString dataGroupHashValue)
		{
			checkValues(dg, dataGroupNumber, dataGroupHashValue);

			dg = DataGroupHash.getInstance(dg);

			checkValues(dg, dataGroupNumber, dataGroupHashValue);

			ASN1InputStream aIn = new ASN1InputStream(dg.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			dg = DataGroupHash.getInstance(seq);

			checkValues(dg, dataGroupNumber, dataGroupHashValue);
		}

		private void checkValues(DataGroupHash dg, int dataGroupNumber, ASN1OctetString dataGroupHashValue)
		{
			if (dg.getDataGroupNumber() != dataGroupNumber)
			{
				fail("group number don't match.");
			}

			if (!dg.getDataGroupHashValue().Equals(dataGroupHashValue))
			{
				fail("hash value don't match.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new DataGroupHashUnitTest());
		}
	}

}