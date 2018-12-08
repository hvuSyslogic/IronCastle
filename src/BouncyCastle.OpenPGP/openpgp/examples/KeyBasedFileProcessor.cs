using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.examples
{

	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using CompressionAlgorithmTags = org.bouncycastle.bcpg.CompressionAlgorithmTags;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcePGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePGPDataEncryptorBuilder;
	using JcePublicKeyDataDecryptorFactoryBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
	using JcePublicKeyKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// A simple utility class that encrypts/decrypts public key based
	/// encryption files.
	/// <para>
	/// To encrypt a file: KeyBasedFileProcessor -e [-a|-ai] fileName publicKeyFile.<br>
	/// If -a is specified the output file will be "ascii-armored".
	/// If -i is specified the output file will be have integrity checking added.
	/// </para>
	/// <para>
	/// To decrypt: KeyBasedFileProcessor -d fileName secretKeyFile passPhrase.
	/// </para>
	/// <para>
	/// Note 1: this example will silently overwrite files, nor does it pay any attention to
	/// the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
	/// will have been used.
	/// </para>
	/// <para>
	/// Note 2: if an empty file name has been specified in the literal data object contained in the
	/// encrypted packet a file with the name filename.out will be generated in the current working directory.
	/// </para>
	/// </summary>
	public class KeyBasedFileProcessor
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

				object message = plainFact.nextObject();

				if (message is PGPCompressedData)
				{
					PGPCompressedData cData = (PGPCompressedData)message;
					JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

					message = pgpFact.nextObject();
				}

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
				byte[] bytes = PGPExampleUtil.compressFile(fileName, CompressionAlgorithmTags_Fields.ZIP);

				PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

				encGen.addMethod((new JcePublicKeyKeyEncryptionMethodGenerator(encKey)).setProvider("BC"));

				OutputStream cOut = encGen.open(@out, bytes.Length);

				cOut.write(bytes);
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
				JavaSystem.err.println("usage: KeyBasedFileProcessor -e|-d [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
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
				JavaSystem.err.println("usage: KeyBasedFileProcessor -d|-e [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
			}
		}
	}

}