namespace org.bouncycastle.openpgp.examples
{

	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentVerifierBuilderProvider;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;

	/// <summary>
	/// A simple utility class that creates seperate signatures for files and verifies them.
	/// <para>
	/// To sign a file: DetachedSignatureProcessor -s [-a] fileName secretKey passPhrase.<br>
	/// If -a is specified the output file will be "ascii-armored".
	/// </para>
	/// <para>
	/// To decrypt: DetachedSignatureProcessor -v  fileName signatureFile publicKeyFile.
	/// </para>
	/// <para>
	/// Note: this example will silently overwrite files.
	/// It also expects that a single pass phrase
	/// will have been used.
	/// </para>
	/// </summary>
	public class DetachedSignatureProcessor
	{
		private static void verifySignature(string fileName, string inputFileName, string keyFileName)
		{
			InputStream @in = new BufferedInputStream(new FileInputStream(inputFileName));
			InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));

			verifySignature(fileName, @in, keyIn);

			keyIn.close();
			@in.close();
		}

		/*
		 * verify the signature in in against the file fileName.
		 */
		private static void verifySignature(string fileName, InputStream @in, InputStream keyIn)
		{
			@in = PGPUtil.getDecoderStream(@in);

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(@in);
			PGPSignatureList p3;

			object o = pgpFact.nextObject();
			if (o is PGPCompressedData)
			{
				PGPCompressedData c1 = (PGPCompressedData)o;

				pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

				p3 = (PGPSignatureList)pgpFact.nextObject();
			}
			else
			{
				p3 = (PGPSignatureList)o;
			}

			PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());


			InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));

			PGPSignature sig = p3.get(0);
			PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

			sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), key);

			int ch;
			while ((ch = dIn.read()) >= 0)
			{
				sig.update((byte)ch);
			}

			dIn.close();

			if (sig.verify())
			{
				JavaSystem.@out.println("signature verified.");
			}
			else
			{
				JavaSystem.@out.println("signature verification failed.");
			}
		}

		private static void createSignature(string inputFileName, string keyFileName, string outputFileName, char[] pass, bool armor)
		{
			InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
			OutputStream @out = new BufferedOutputStream(new FileOutputStream(outputFileName));

			createSignature(inputFileName, keyIn, @out, pass, armor);

			@out.close();
			keyIn.close();
		}

		private static void createSignature(string fileName, InputStream keyIn, OutputStream @out, char[] pass, bool armor)
		{
			if (armor)
			{
				@out = new ArmoredOutputStream(@out);
			}

			PGPSecretKey pgpSec = PGPExampleUtil.readSecretKey(keyIn);
			PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(pass));
			PGPSignatureGenerator sGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1)).setProvider("BC"));

			sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

			BCPGOutputStream bOut = new BCPGOutputStream(@out);

			InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));

			int ch;
			while ((ch = fIn.read()) >= 0)
			{
				sGen.update((byte)ch);
			}

			fIn.close();

			sGen.generate().encode(bOut);

			if (armor)
			{
				@out.close();
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			if (args[0].Equals("-s"))
			{
				if (args[1].Equals("-a"))
				{
					createSignature(args[2], args[3], args[2] + ".asc", args[4].ToCharArray(), true);
				}
				else
				{
					createSignature(args[1], args[2], args[1] + ".bpg", args[3].ToCharArray(), false);
				}
			}
			else if (args[0].Equals("-v"))
			{
				verifySignature(args[1], args[2], args[3]);
			}
			else
			{
				JavaSystem.err.println("usage: DetachedSignatureProcessor [-s [-a] file keyfile passPhrase]|[-v file sigFile keyFile]");
			}
		}
	}

}