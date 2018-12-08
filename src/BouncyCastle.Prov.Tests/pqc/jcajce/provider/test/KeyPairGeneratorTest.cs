using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	public abstract class KeyPairGeneratorTest : FlexiTest
	{

		protected internal KeyPairGenerator kpg;

		protected internal KeyFactory kf;

		public void performKeyPairEncodingTest(KeyPair keyPair)
		{
			try
			{
				PublicKey pubKey = keyPair.getPublic();
				PrivateKey privKey = keyPair.getPrivate();

				byte[] encPubKey = pubKey.getEncoded();
				byte[] encPrivKey = privKey.getEncoded();

				X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encPubKey);
				PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encPrivKey);

				PublicKey decPubKey = kf.generatePublic(pubKeySpec);
				PrivateKey decPrivKey = kf.generatePrivate(privKeySpec);

				assertEquals(pubKey, decPubKey);
				assertEquals(privKey, decPrivKey);
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
				fail(e);
			}
		}

	}

}