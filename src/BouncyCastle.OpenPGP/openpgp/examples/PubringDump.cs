using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.examples
{

	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Basic class which just lists the contents of the public key file passed
	/// as an argument. If the file contains more than one "key ring" they are
	/// listed in the order found.
	/// </summary>
	public class PubringDump
	{
		public static string getAlgorithm(int algId)
		{
			switch (algId)
			{
			case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
				return "RSA_GENERAL";
			case PublicKeyAlgorithmTags_Fields.RSA_ENCRYPT:
				return "RSA_ENCRYPT";
			case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
				return "RSA_SIGN";
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT:
				return "ELGAMAL_ENCRYPT";
			case PublicKeyAlgorithmTags_Fields.DSA:
				return "DSA";
			case PublicKeyAlgorithmTags_Fields.ECDH:
				return "ECDH";
			case PublicKeyAlgorithmTags_Fields.ECDSA:
				return "ECDSA";
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
				return "ELGAMAL_GENERAL";
			case PublicKeyAlgorithmTags_Fields.DIFFIE_HELLMAN:
				return "DIFFIE_HELLMAN";
			}

			return "unknown";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			//
			// Read the public key rings
			//
			PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream(args[0])), new JcaKeyFingerprintCalculator());

			Iterator rIt = pubRings.getKeyRings();

			while (rIt.hasNext())
			{
				PGPPublicKeyRing pgpPub = (PGPPublicKeyRing)rIt.next();

				try
				{
					pgpPub.getPublicKey();
				}
				catch (Exception e)
				{
					Console.WriteLine(e.ToString());
					Console.Write(e.StackTrace);
					continue;
				}

				Iterator it = pgpPub.getPublicKeys();
				bool first = true;
				while (it.hasNext())
				{
					PGPPublicKey pgpKey = (PGPPublicKey)it.next();

					if (first)
					{
						JavaSystem.@out.println("Key ID: " + pgpKey.getKeyID().ToString("x"));
						first = false;
					}
					else
					{
						JavaSystem.@out.println("Key ID: " + pgpKey.getKeyID().ToString("x") + " (subkey)");
					}
					JavaSystem.@out.println("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
					JavaSystem.@out.println("            Fingerprint: " + StringHelper.NewString(Hex.encode(pgpKey.getFingerprint())));
				}
			}
		}
	}

}