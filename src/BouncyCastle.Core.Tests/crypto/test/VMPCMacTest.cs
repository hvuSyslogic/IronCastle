namespace org.bouncycastle.crypto.test
{
	using VMPCMac = org.bouncycastle.crypto.macs.VMPCMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class VMPCMacTest : SimpleTest
	{
		public override string getName()
		{
			return "VMPC-MAC";
		}

		public static void Main(string[] args)
		{
			runTest(new VMPCMacTest());
		}

		internal static byte[] output1 = Hex.decode("9BDA16E2AD0E284774A3ACBC8835A8326C11FAAD");

		public override void performTest()
		{
			CipherParameters kp = new KeyParameter(Hex.decode("9661410AB797D8A9EB767C21172DF6C7"));
			CipherParameters kpwiv = new ParametersWithIV(kp, Hex.decode("4B5C2F003E67F39557A8D26F3DA2B155"));

			byte[] m = new byte[512];

			int offset = 117;
			for (int i = 0; i < 256; i++)
			{
				m[offset + i] = (byte) i;
			}

			VMPCMac mac = new VMPCMac();
			mac.init(kpwiv);

			mac.update(m, offset, 256);

			byte[] @out = new byte[20];
			mac.doFinal(@out, 0);

			if (!Arrays.areEqual(@out, output1))
			{
				fail("Fail", StringHelper.NewString(Hex.encode(output1)), StringHelper.NewString(Hex.encode(@out)));
			}
		}
	}

}