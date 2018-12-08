using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using McElieceKeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;

	public class McElieceCipherTest : AsymmetricBlockCipherTest
	{

		public override void setUp()
		{
			base.setUp();

			try
			{
				kpg = KeyPairGenerator.getInstance("McEliece");
				cipher = Cipher.getInstance("McEliece");
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}


		}

		public virtual void testEnDecryption_9_33()
		{
			McElieceKeyGenParameterSpec @params = new McElieceKeyGenParameterSpec(9, 33);
			kpg.initialize(@params);
			performEnDecryptionTest(2, 10, @params);
		}

		public virtual void testEnDecryption_11_50()
		{
			McElieceKeyGenParameterSpec @params = new McElieceKeyGenParameterSpec(11, 50);
			kpg.initialize(@params);
			performEnDecryptionTest(2, 10, @params);
		}


	}

}