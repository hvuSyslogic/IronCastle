namespace org.bouncycastle.openpgp.examples
{

	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using NotationData = org.bouncycastle.bcpg.sig.NotationData;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;

	/// <summary>
	/// A simple utility class that directly signs a public key and writes the signed key to "SignedKey.asc" in 
	/// the current working directory.
	/// <para>
	/// To sign a key: DirectKeySignature secretKeyFile secretKeyPass publicKeyFile(key to be signed) NotationName NotationValue.
	/// </para>
	/// </para><para>
	/// To display a NotationData packet from a publicKey previously signed: DirectKeySignature signedPublicKeyFile.
	/// </para><para>
	/// <b>Note</b>: this example will silently overwrite files, nor does it pay any attention to
	/// the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
	/// will have been used.
	/// </summary>
	public class DirectKeySignature
	{
		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			if (args.Length == 1)
			{
				PGPPublicKeyRing ring = new PGPPublicKeyRing(PGPUtil.getDecoderStream(new FileInputStream(args[0])), new JcaKeyFingerprintCalculator());
				PGPPublicKey key = ring.getPublicKey();

				// iterate through all direct key signautures and look for NotationData subpackets
				Iterator iter = key.getSignaturesOfType(PGPSignature.DIRECT_KEY);
				while (iter.hasNext())
				{
					PGPSignature sig = (PGPSignature)iter.next();

					JavaSystem.@out.println("Signature date is: " + sig.getHashedSubPackets().getSignatureCreationTime());

					NotationData[] data = sig.getHashedSubPackets().getNotationDataOccurrences(); //.getSubpacket(SignatureSubpacketTags.NOTATION_DATA);

					for (int i = 0; i < data.Length; i++)
					{
						JavaSystem.@out.println("Found Notation named '" + data[i].getNotationName() + "' with content '" + data[i].getNotationValue() + "'.");
					}
				}
			}
			else if (args.Length == 5)
			{
				// gather command line arguments
				PGPSecretKeyRing secRing = new PGPSecretKeyRing(PGPUtil.getDecoderStream(new FileInputStream(args[0])), new JcaKeyFingerprintCalculator());
				string secretKeyPass = args[1];
				PGPPublicKeyRing ring = new PGPPublicKeyRing(PGPUtil.getDecoderStream(new FileInputStream(args[2])), new JcaKeyFingerprintCalculator());
				string notationName = args[3];
				string notationValue = args[4];

				// create the signed keyRing
				PGPPublicKeyRing sRing = new PGPPublicKeyRing(new ByteArrayInputStream(signPublicKey(secRing.getSecretKey(), secretKeyPass, ring.getPublicKey(), notationName, notationValue)), new JcaKeyFingerprintCalculator());
				ring = sRing;

				// write the created keyRing to file
				ArmoredOutputStream @out = new ArmoredOutputStream(new FileOutputStream("SignedKey.asc"));
				sRing.encode(@out);
				@out.flush();
				@out.close();
			}
			else
			{
				JavaSystem.err.println("usage: DirectKeySignature secretKeyFile secretKeyPass publicKeyFile(key to be signed) NotationName NotationValue");
				JavaSystem.err.println("or: DirectKeySignature signedPublicKeyFile");

			}
		}

		private static byte[] signPublicKey(PGPSecretKey secretKey, string secretKeyPass, PGPPublicKey keyToBeSigned, string notationName, string notationValue)
		{
			PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(secretKeyPass.ToCharArray()));

			PGPSignatureGenerator sGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1)).setProvider("BC"));

			sGen.init(PGPSignature.DIRECT_KEY, pgpPrivKey);

			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

			bool isHumanReadable = true;

			spGen.setNotationData(true, isHumanReadable, notationName, notationValue);

			PGPSignatureSubpacketVector packetVector = spGen.generate();

			sGen.setHashedSubpackets(packetVector);

			return PGPPublicKey.addCertification(keyToBeSigned, sGen.generate()).getEncoded();
		}
	}

}