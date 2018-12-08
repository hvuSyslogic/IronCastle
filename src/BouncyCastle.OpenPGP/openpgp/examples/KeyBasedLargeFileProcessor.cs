using System;

namespace org.bouncycastle.openpgp.examples
{

	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcePGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePGPDataEncryptorBuilder;
	using JcePublicKeyDataDecryptorFactoryBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
	using JcePublicKeyKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// A simple utility class that encrypts/decrypts public key based
	/// encryption large files.
	/// <para>
	/// To encrypt a file: KeyBasedLargeFileProcessor -e [-a|-ai] fileName publicKeyFile.<br>
	/// If -a is specified the output file will be "ascii-armored".
	/// If -i is specified the output file will be have integrity checking added.
	/// </para>
	/// <para>
	/// To decrypt: KeyBasedLargeFileProcessor -d fileName secretKeyFile passPhrase.
	/// </para>
	/// <para>
	/// Note 1: this example will silently overwrite files, nor does it pay any attention to
	/// the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
	/// will have been used.
	/// </para>
	/// <para>
	/// Note 2: this example generates partial packets to encode the file, the output it generates
	/// will not be readable by older PGP products or products that don't support partial packet 
	/// encoding.
	/// </para>
	/// <para>
	/// Note 3: if an empty file name has been specified in the literal data object contained in the
	/// encrypted packet a file with the name filename.out will be generated in the current working directory.
	/// </para>
	/// </summary>
	public class KeyBasedLargeFileProcessor
	{
		private static void decryptFile(string inputFileName, string keyFileName, char[] passwd, string defaultFileName)
		{
			InputStream @in = new BufferedInputStream(new FileInputStream(inputFileName));
			InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
			decryptFile(@in, keyIn, passwd, defaultFileName);
			keyIn.close();
			@in.close();
		}

		/// <summary>
		/// decrypt the passed in message stream
		/// </summary>
		private static void decryptFile(InputStream @in, InputStream keyIn, char[] passwd, string defaultFileName)
		{
			@in = PGPUtil.getDecoderStream(@in);

			try
			{
				JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(@in);
				PGPEncryptedDataList enc;

				object o = pgpF.nextObject();
				//
				// the first object might be a PGP marker packet.
				//
				if (o is PGPEncryptedDataList)
				{
					enc = (PGPEncryptedDataList)o;
				}
				else
				{
					enc = (PGPEncryptedDataList)pgpF.nextObject();
				}

				//
				// find the secret key
				//
				Iterator it = enc.getEncryptedDataObjects();
				PGPPrivateKey sKey = null;
				PGPPublicKeyEncryptedData pbe = null;
				PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

				while (sKey == null && it.hasNext())
				{
					pbe = (PGPPublicKeyEncryptedData)it.next();

					sKey = PGPExampleUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
				}

				if (sKey == null)
				{
					throw new IllegalArgumentException("secret key for message not found.");
				}

				InputStream clear = pbe.getDataStream((new JcePublicKeyDataDecryptorFactoryBuilder()).setProvider("BC").build(sKey));

				JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

				PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();

				InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
				JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);

				object message = pgpFact.nextObject();

				if (message is PGPLiteralData)
				{
					PGPLiteralData ld = (PGPLiteralData)message;

					string outFileName = ld.getFileName();
					if (outFileName.Length == 0)
					{
						outFileName = defaultFileName;
					}

					InputStream unc = ld.getInputStream();
					OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFileName));

					Streams.pipeAll(unc, fOut);

					fOut.close();
				}
				else if (message is PGPOnePassSignatureList)
				{
					throw new PGPException("encrypted message contains a signed message - not literal data.");
				}
				else
				{
					throw new PGPException("message is not a simple encrypted file - type unknown.");
				}

				if (pbe.isIntegrityProtected())
				{
					if (!pbe.verify())
					{
						JavaSystem.err.println("message failed integrity check");
					}
					else
					{
						JavaSystem.err.println("message integrity check passed");
					}
				}
				else
				{
					JavaSystem.err.println("no message integrity check");
				}
			}
			catch (PGPException e)
			{
				JavaSystem.err.println(e);
				if (e.getUnderlyingException() != null)
				{
					Console.WriteLine(e.getUnderlyingException().ToString());
					Console.Write(e.getUnderlyingException().StackTrace);
				}
			}
		}

		private static void encryptFile(string outputFileName, string inputFileName, string encKeyFileName, bool armor, bool withIntegrityCheck)
		{
			OutputStream @out = new BufferedOutputStream(new FileOutputStream(outputFileName));
			PGPPublicKey encKey = PGPExampleUtil.readPublicKey(encKeyFileName);
			encryptFile(@out, inputFileName, encKey, armor, withIntegrityCheck);
			@out.close();
		}

		private static void encryptFile(OutputStream @out, string fileName, PGPPublicKey encKey, bool armor, bool withIntegrityCheck)
		{
			if (armor)
			{
				@out = new ArmoredOutputStream(@out);
			}

			try
			{
				PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

				cPk.addMethod((new JcePublicKeyKeyEncryptionMethodGenerator(encKey)).setProvider("BC"));

				OutputStream cOut = cPk.open(@out, new byte[1 << 16]);

				PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

				PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);

				comData.close();

				cOut.close();

				if (armor)
				{
					@out.close();
				}
			}
			catch (PGPException e)
			{
				JavaSystem.err.println(e);
				if (e.getUnderlyingException() != null)
				{
					Console.WriteLine(e.getUnderlyingException().ToString());
					Console.Write(e.getUnderlyingException().StackTrace);
				}
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			if (args.Length == 0)
			{
				JavaSystem.err.println("usage: KeyBasedLargeFileProcessor -e|-d [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
				return;
			}

			if (args[0].Equals("-e"))
			{
				if (args[1].Equals("-a") || args[1].Equals("-ai") || args[1].Equals("-ia"))
				{
					encryptFile(args[2] + ".asc", args[2], args[3], true, (args[1].IndexOf('i') > 0));
				}
				else if (args[1].Equals("-i"))
				{
					encryptFile(args[2] + ".bpg", args[2], args[3], false, true);
				}
				else
				{
					encryptFile(args[1] + ".bpg", args[1], args[2], false, false);
				}
			}
			else if (args[0].Equals("-d"))
			{
				decryptFile(args[1], args[2], args[3].ToCharArray(), (new File(args[1])).getName() + ".out");
			}
			else
			{
				JavaSystem.err.println("usage: KeyBasedLargeFileProcessor -d|-e [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
			}
		}
	}

}