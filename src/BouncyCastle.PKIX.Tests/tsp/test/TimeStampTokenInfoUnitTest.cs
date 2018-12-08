using org.bouncycastle.tsp;

using System;

namespace org.bouncycastle.tsp.test
{

	using Assert = junit.framework.Assert;
	using TestCase = junit.framework.TestCase;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using TSTInfo = org.bouncycastle.asn1.tsp.TSTInfo;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class TimeStampTokenInfoUnitTest : TestCase
	{
		private static readonly byte[] tstInfo1 = Hex.decode("303e02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000" + "020118180f32303035313130313038313732315a");

		private static readonly byte[] tstInfo2 = Hex.decode("304c02010106022a033021300906052b0e03021a05000414ffffffffffffffffffffffffffffffffffffffff" + "020117180f32303035313130313038323934355a3009020103800101810102020164");

		private static readonly byte[] tstInfo3 = Hex.decode("304f02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000" + "020117180f32303035313130313038343733355a30090201038001018101020101ff020164");

		private static readonly byte[] tstInfoDudDate = Hex.decode("303e02010106022a033021300906052b0e03021a050004140000000000000000000000000000000000000000" + "020118180f32303056313130313038313732315a");

		public virtual void testTstInfo1()
		{
			TimeStampTokenInfo tstInfo = getTimeStampTokenInfo(tstInfo1);

			//
			// verify
			//
			GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

			assertNull(accuracy);

			assertEquals(new BigInteger("24"), tstInfo.getSerialNumber());

			assertEquals(1130833041000L, tstInfo.getGenTime().Ticks);

			assertEquals("1.2.3", tstInfo.getPolicy().getId());

			assertEquals(false, tstInfo.isOrdered());

			assertNull(tstInfo.getNonce());

			Assert.assertEquals(TSPAlgorithms_Fields.SHA1, tstInfo.getMessageImprintAlgOID());

			assertTrue(Arrays.areEqual(new byte[20], tstInfo.getMessageImprintDigest()));

			assertTrue(Arrays.areEqual(tstInfo1, tstInfo.getEncoded()));
		}

		public virtual void testTstInfo2()
		{
			TimeStampTokenInfo tstInfo = getTimeStampTokenInfo(tstInfo2);

			//
			// verify
			//
			GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

			assertEquals(3, accuracy.getSeconds());
			assertEquals(1, accuracy.getMillis());
			assertEquals(2, accuracy.getMicros());

			assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

			assertEquals(1130833785000L, tstInfo.getGenTime().Ticks);

			assertEquals("1.2.3", tstInfo.getPolicy().getId());

			assertEquals(false, tstInfo.isOrdered());

			assertEquals(tstInfo.getNonce(), BigInteger.valueOf(100));

			assertTrue(Arrays.areEqual(Hex.decode("ffffffffffffffffffffffffffffffffffffffff"), tstInfo.getMessageImprintDigest()));

			assertTrue(Arrays.areEqual(tstInfo2, tstInfo.getEncoded()));
		}

		public virtual void testTstInfo3()
		{
			TimeStampTokenInfo tstInfo = getTimeStampTokenInfo(tstInfo3);

			//
			// verify
			//
			GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

			assertEquals(3, accuracy.getSeconds());
			assertEquals(1, accuracy.getMillis());
			assertEquals(2, accuracy.getMicros());

			assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

			assertEquals(1130834855000L, tstInfo.getGenTime().Ticks);

			assertEquals("1.2.3", tstInfo.getPolicy().getId());

			assertEquals(true, tstInfo.isOrdered());

			assertEquals(tstInfo.getNonce(), BigInteger.valueOf(100));

			assertEquals(TSPAlgorithms_Fields.SHA1, tstInfo.getMessageImprintAlgOID());

			assertTrue(Arrays.areEqual(new byte[20], tstInfo.getMessageImprintDigest()));

			assertTrue(Arrays.areEqual(tstInfo3, tstInfo.getEncoded()));
		}

		public virtual void testTstInfoDudDate()
		{
			try
			{
				getTimeStampTokenInfo(tstInfoDudDate);

				fail("dud date not detected.");
			}
			catch (TSPException)
			{
				// expected
			}
		}

		private TimeStampTokenInfo getTimeStampTokenInfo(byte[] tstInfo)
		{
			ASN1InputStream aIn = new ASN1InputStream(tstInfo);
			TSTInfo info = TSTInfo.getInstance(aIn.readObject());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final Constructor constructor = org.bouncycastle.tsp.TimeStampTokenInfo.class.getDeclaredConstructor(org.bouncycastle.asn1.tsp.TSTInfo.class);
			Constructor constructor = typeof(TimeStampTokenInfo).getDeclaredConstructor(typeof(TSTInfo));

			constructor.setAccessible(true);

			try
			{
				return (TimeStampTokenInfo)constructor.newInstance(new object[]{info});
			}
			catch (InvocationTargetException e)
			{
				throw (Exception)e.getTargetException();
			}
		}
	}

}