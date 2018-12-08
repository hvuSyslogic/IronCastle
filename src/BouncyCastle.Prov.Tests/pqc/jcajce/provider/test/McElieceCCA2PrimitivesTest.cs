using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using BCMcElieceCCA2PrivateKey = org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
	using BCMcElieceCCA2PublicKey = org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
	using McElieceCCA2Primitives = org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceCCA2Primitives;
	using McElieceKeyGenParameterSpec = org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
	using GF2Vector = org.bouncycastle.pqc.math.linearalgebra.GF2Vector;


	public class McElieceCCA2PrimitivesTest : FlexiTest
	{

		internal KeyPairGenerator kpg;

		public override void setUp()
		{
			base.setUp();
			try
			{
				kpg = KeyPairGenerator.getInstance("McElieceKobaraImai");
			}
			catch (NoSuchAlgorithmException e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}
		}

		public virtual void testPrimitives()
		{
			int m = 11;
			int t = 50;
			initKPG(m, t);
			int n = 1 << m;

			KeyPair pair = kpg.genKeyPair();
			BCMcElieceCCA2PublicKey pubKey = (BCMcElieceCCA2PublicKey)pair.getPublic();
			BCMcElieceCCA2PrivateKey privKey = (BCMcElieceCCA2PrivateKey)pair.getPrivate();

			GF2Vector plaintext = new GF2Vector(pubKey.getK(), sr);
			GF2Vector errors = new GF2Vector(n, t, sr);

			GF2Vector ciphertext = McElieceCCA2Primitives.encryptionPrimitive(pubKey, plaintext, errors);

			GF2Vector[] dec = McElieceCCA2Primitives.decryptionPrimitive(privKey, ciphertext);
			GF2Vector plaintextAgain = dec[0];
			GF2Vector errorsAgain = dec[1];

			assertEquals(plaintext, plaintextAgain);
			assertEquals(errors, errorsAgain);
		}

		/// <summary>
		/// Initialize the key pair generator with the given parameters.
		/// </summary>
		private void initKPG(int m, int t)
		{
			McElieceKeyGenParameterSpec @params = new McElieceKeyGenParameterSpec(m, t);
			kpg.initialize(@params);
		}

	}

}