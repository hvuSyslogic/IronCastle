namespace org.bouncycastle.util.io.pem.test
{

	using TestCase = junit.framework.TestCase;

	public class AllTests : TestCase
	{
		public virtual void testPemLength()
		{
			for (int i = 1; i != 60; i++)
			{
				lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[i]);
			}

			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[100]);
			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[101]);
			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[102]);
			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[103]);

			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1000]);
			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1001]);
			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1002]);
			lengthTest("CERTIFICATE", Collections.EMPTY_LIST, new byte[1003]);

			List headers = new ArrayList();

			headers.add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
			headers.add(new PemHeader("DEK-Info", "DES3,0001020304050607"));

			lengthTest("RSA PRIVATE KEY", headers, new byte[103]);
		}

		private void lengthTest(string type, List headers, byte[] data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PemWriter pWrt = new PemWriter(new OutputStreamWriter(bOut));

			PemObject pemObj = new PemObject(type, headers, data);
			pWrt.writeObject(pemObj);

			pWrt.close();

			assertEquals(bOut.toByteArray().length, pWrt.getOutputSize(pemObj));
		}
	}
}