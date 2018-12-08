using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.examples
{

	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcaPGPKeyPair = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPKeyPair;
	using JcePBESecretKeyEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyEncryptorBuilder;

	/// <summary>
	/// A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
	/// <para>
	/// usage: RSAKeyPairGenerator [-a] identity passPhrase
	/// </para>
	/// <para>
	/// Where identity is the name to be associated with the public key. The keys are placed 
	/// in the files pub.[asc|bpg] and secret.[asc|bpg].
	/// </para>
	/// </summary>
	public class RSAKeyPairGenerator
	{
		private static void exportKeyPair(OutputStream secretOut, OutputStream publicOut, KeyPair pair, string identity, char[] passPhrase, bool armor)
		{
			if (armor)
			{
				secretOut = new ArmoredOutputStream(secretOut);
			}

			PGPDigestCalculator sha1Calc = (new JcaPGPDigestCalculatorProviderBuilder()).build().get(HashAlgorithmTags_Fields.SHA1);
			PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, DateTime.Now);
			PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags_Fields.SHA1), (new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)).setProvider("BC").build(passPhrase));

			secretKey.encode(secretOut);

			secretOut.close();

			if (armor)
			{
				publicOut = new ArmoredOutputStream(publicOut);
			}

			PGPPublicKey key = secretKey.getPublicKey();

			key.encode(publicOut);

			publicOut.close();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

			kpg.initialize(1024);

			KeyPair kp = kpg.generateKeyPair();

			if (args.Length < 2)
			{
				JavaSystem.@out.println("RSAKeyPairGenerator [-a] identity passPhrase");
				System.exit(0);
			}

			if (args[0].Equals("-a"))
			{
				if (args.Length < 3)
				{
					JavaSystem.@out.println("RSAKeyPairGenerator [-a] identity passPhrase");
					System.exit(0);
				}

				FileOutputStream out1 = new FileOutputStream("secret.asc");
				FileOutputStream out2 = new FileOutputStream("pub.asc");

				exportKeyPair(out1, out2, kp, args[1], args[2].ToCharArray(), true);
			}
			else
			{
				FileOutputStream out1 = new FileOutputStream("secret.bpg");
				FileOutputStream out2 = new FileOutputStream("pub.bpg");

				exportKeyPair(out1, out2, kp, args[0], args[1].ToCharArray(), false);
			}
		}
	}

}