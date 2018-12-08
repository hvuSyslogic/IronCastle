using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using McElieceCCA2KeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;


	public class McElieceKobaraImaiCipherTest : AsymmetricHybridCipherTest
	{

		public override void setUp()
		{
			base.setUp();
			try
			{
				kpg = KeyPairGenerator.getInstance("McElieceKobaraImai");
				cipher = Cipher.getInstance("McElieceKobaraImai");
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
		public virtual void testEnDecryption_SHA256_11_50()
		{
			// initialize key pair generator
			AlgorithmParameterSpec kpgParams = new McElieceCCA2KeyGenParameterSpec(11, 50);
			kpg.initialize(kpgParams);

			performEnDecryptionTest(0, 10, 32, null); // TODO:  McElieceKobaraImai is broken
		}

	}

}