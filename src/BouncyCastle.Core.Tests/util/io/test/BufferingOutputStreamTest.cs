﻿namespace org.bouncycastle.util.io.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class BufferingOutputStreamTest : SimpleTest
	{
		public override string getName()
		{
			return "BufferingStreamTest";
		}

		public override void performTest()
		{
			SecureRandom random = new SecureRandom();

			for (int i = 1; i != 256; i++)
			{
				byte[] data = new byte[i];

				random.nextBytes(data);

				checkStream(data, 16);
				checkStream(data, 33);
				checkStream(data, 128);
			}
		}

		private void checkStream(byte[] data, int bufsize)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BufferingOutputStream bfOut = new BufferingOutputStream(bOut, bufsize);

			for (int i = 0; i != 10; i++)
			{
				bfOut.write(data[0]);
				bfOut.write(data, 1, data.Length - 1);
			}

			bfOut.close();

			byte[] output = bOut.toByteArray();

			for (int i = 0; i != 10; i++)
			{
				 for (int j = 0; j != data.Length; j++)
				 {
					 if (output[i * data.Length + j] != data[j])
					 {
						 fail("data mismatch!");
					 }
				 }
			}
		}

		public static void Main(string[] args)
		{
			runTest(new BufferingOutputStreamTest());
		}
	}

}