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
	/// A simple utility class that signs and verifies files.
	/// <para>
	/// To sign a file: SignedFileProcessor -s [-a] fileName secretKey passPhrase.<br>
	/// If -a is specified the output file will be "ascii-armored".
	/// </para>
	/// <para>
	/// To decrypt: SignedFileProcessor -v fileName publicKeyFile.
	/// </para>
	/// <para>
	/// <b>Note</b>: this example will silently overwrite files, nor does it pay any attention to
	/// the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
	/// will have been used.
	/// </para>
	/// <para>
	/// <b>Note</b>: the example also makes use of PGP compression. If you are having difficulty getting it
	/// to interoperate with other PGP programs try removing the use of compression first.
	/// </para>
	/// </summary>
	public class SignedFileProcessor
	{
		/*
		 * verify the passed in file as being correctly signed.
		 */
		private static void verifyFile(InputStream @in, InputStream keyIn)
		{
			@in = PGPUtil.getDecoderStream(@in);

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(@in);

			PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();

			PGPOnePassSignature ops = p1.get(0);

			PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();

			InputStream dIn = p2.getInputStream();
			int ch;
			PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

			PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
			FileOutputStream @out = new FileOutputStream(p2.getFileName());

			ops.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), key);

			while ((ch = dIn.read()) >= 0)
			{
				ops.update((byte)ch);
				@out.write(ch);
			}

			@out.close();

			PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

			if (ops.verify(p3.get(0)))
			{
				JavaSystem.@out.println("signature verified.");
			}
			else
			{
				JavaSystem.@out.println("signature verification failed.");
			}
		}

		/// <summary>
		/// Generate an encapsulated signed file.
		/// </summary>
		/// <param name="fileName"> </param>
		/// <param name="keyIn"> </param>
		/// <param name="out"> </param>
		/// <param name="pass"> </param>
		/// <param name="armor"> </param>
		/// <exception cref="IOException"> </exception>
		/// <exception cref="NoSuchAlgorithmException"> </exception>
		/// <exception cref="NoSuchProviderException"> </exception>
		/// <exception cref="PGPException"> </exception>
		/// <exception cref="SignatureException"> </exception>
		private static void signFile(string fileName, InputStream keyIn, OutputStream @out, char[] pass, bool armor)
		{
			if (armor)
			{
				@out = new ArmoredOutputStream(@out);
			}

			PGPSecretKey pgpSec = PGPExampleUtil.readSecretKey(keyIn);
			PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(pass));
			PGPSignatureGenerator sGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1)).setProvider("BC"));

			sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

			Iterator it = pgpSec.getPublicKey().getUserIDs();
			if (it.hasNext())
			{
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

				spGen.setSignerUserID(false, (string)it.next());
				sGen.setHashedSubpackets(spGen.generate());
			}

			PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);

			BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(@out));

			sGen.generateOnePassVersion(false).encode(bOut);

			File file = new File(fileName);
			PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
			OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
			FileInputStream fIn = new FileInputStream(file);
			int ch;

			while ((ch = fIn.read()) >= 0)
			{
				lOut.write(ch);
				sGen.update((byte)ch);
			}

			lGen.close();

			sGen.generate().encode(bOut);

			cGen.close();

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
					FileInputStream keyIn = new FileInputStream(args[3]);
					FileOutputStream @out = new FileOutputStream(args[2] + ".asc");

					signFile(args[2], keyIn, @out, args[4].ToCharArray(), true);
				}
				else
				{
					FileInputStream keyIn = new FileInputStream(args[2]);
					FileOutputStream @out = new FileOutputStream(args[1] + ".bpg");

					signFile(args[1], keyIn, @out, args[3].ToCharArray(), false);
				}
			}
			else if (args[0].Equals("-v"))
			{
				FileInputStream @in = new FileInputStream(args[1]);
				FileInputStream keyIn = new FileInputStream(args[2]);

				verifyFile(@in, keyIn);
			}
			else
			{
				JavaSystem.err.println("usage: SignedFileProcessor -v|-s [-a] file keyfile [passPhrase]");
			}
		}
	}
}