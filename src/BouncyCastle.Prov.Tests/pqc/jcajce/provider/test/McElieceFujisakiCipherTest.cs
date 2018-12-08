using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using McElieceCCA2KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;


	public class McElieceFujisakiCipherTest : AsymmetricHybridCipherTest
	{

		public override void setUp()
		{
			base.setUp();
			try
			{
				kpg = KeyPairGenerator.getInstance("McElieceFujisaki");
				cipher = Cipher.getInstance("McElieceFujisaki");
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}

		}

		/// <summary>
		/// Test encryption and decryption performance for SHA256 message digest and parameters
		/// m=11, t=50.
		/// </summary>

		public virtual void testEnDecryption_SHA1_11_50()
		{
			// initialize key pair generator
			McElieceCCA2KeyGenParameterSpec kpgParams = new McElieceCCA2KeyGenParameterSpec(11, 50, McElieceCCA2KeyGenParameterSpec.SHA1);
			kpg.initialize(kpgParams);

			// perform test
			performEnDecryptionTest(1, 10, 32, null);
		}

		public virtual void testEnDecryption_SHA224_11_50()
		{
			// initialize key pair generator
			McElieceCCA2KeyGenParameterSpec kpgParams = new McElieceCCA2KeyGenParameterSpec(11, 50, McElieceCCA2KeyGenParameterSpec.SHA224);
			kpg.initialize(kpgParams);

			// perform test
			performEnDecryptionTest(1, 10, 32, null);
		}

		public virtual void testEnDecryption_SHA256_11_50()
		{
			// initialize key pair generator
			McElieceCCA2KeyGenParameterSpec kpgParams = new McElieceCCA2KeyGenParameterSpec(11, 50, McElieceCCA2KeyGenParameterSpec.SHA256);
			kpg.initialize(kpgParams);

			// perform test
			performEnDecryptionTest(1, 10, 32, null);
		}
	}

}