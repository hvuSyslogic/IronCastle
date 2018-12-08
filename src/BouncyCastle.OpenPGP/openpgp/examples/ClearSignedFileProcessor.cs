using System;

namespace org.bouncycastle.openpgp.examples
{

	using ArmoredInputStream = org.bouncycastle.bcpg.ArmoredInputStream;
	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentSignerBuilder;
	using JcaPGPContentVerifierBuilderProvider = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPContentVerifierBuilderProvider;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A simple utility class that creates clear signed files and verifies them.
	/// <para>
	/// To sign a file: ClearSignedFileProcessor -s fileName secretKey passPhrase.<br>
	/// </para>
	/// <para>
	/// To decrypt: ClearSignedFileProcessor -v fileName signatureFile publicKeyFile.
	/// </para>
	/// </summary>
	public class ClearSignedFileProcessor
	{
		private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
		{
			bOut.reset();

			int lookAhead = -1;
			int ch;

			while ((ch = fIn.read()) >= 0)
			{
				bOut.write(ch);
				if (ch == '\r' || ch == '\n')
				{
					lookAhead = readPassedEOL(bOut, ch, fIn);
					break;
				}
			}

			return lookAhead;
		}

		private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
		{
			bOut.reset();

			int ch = lookAhead;

			do
			{
				bOut.write(ch);
				if (ch == '\r' || ch == '\n')
				{
					lookAhead = readPassedEOL(bOut, ch, fIn);
					break;
				}
			} while ((ch = fIn.read()) >= 0);

			if (ch < 0)
			{
				lookAhead = -1;
			}

			return lookAhead;
		}

		private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
		{
			int lookAhead = fIn.read();

			if (lastCh == '\r' && lookAhead == '\n')
			{
				bOut.write(lookAhead);
				lookAhead = fIn.read();
			}

			return lookAhead;
		}

		/*
		 * verify a clear text signed file
		 */
		private static void verifyFile(InputStream @in, InputStream keyIn, string resultName)
		{
			ArmoredInputStream aIn = new ArmoredInputStream(@in);
			OutputStream @out = new BufferedOutputStream(new FileOutputStream(resultName));



			//
			// write out signed section using the local line separator.
			// note: trailing white space needs to be removed from the end of
			// each line RFC 4880 Section 7.1
			//
			ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
			int lookAhead = readInputLine(lineOut, aIn);
			byte[] lineSep = getLineSeparator();

			if (lookAhead != -1 && aIn.isClearText())
			{
				byte[] line = lineOut.toByteArray();
				@out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
				@out.write(lineSep);

				while (lookAhead != -1 && aIn.isClearText())
				{
					lookAhead = readInputLine(lineOut, lookAhead, aIn);

					line = lineOut.toByteArray();
					@out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
					@out.write(lineSep);
				}
			}
			else
			{
				// a single line file
				if (lookAhead != -1)
				{
					byte[] line = lineOut.toByteArray();
					@out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
					@out.write(lineSep);
				}
			}

			@out.close();

			PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(keyIn, new JcaKeyFingerprintCalculator());

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
			PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
			PGPSignature sig = p3.get(0);

			PGPPublicKey publicKey = pgpRings.getPublicKey(sig.getKeyID());
			sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider("BC"), publicKey);

			//
			// read the input, making sure we ignore the last newline.
			//

			InputStream sigIn = new BufferedInputStream(new FileInputStream(resultName));

			lookAhead = readInputLine(lineOut, sigIn);

			processLine(sig, lineOut.toByteArray());

			if (lookAhead != -1)
			{
				do
				{
					lookAhead = readInputLine(lineOut, lookAhead, sigIn);

					sig.update((byte)'\r');
					sig.update((byte)'\n');

					processLine(sig, lineOut.toByteArray());
				} while (lookAhead != -1);
			}

			sigIn.close();

			if (sig.verify())
			{
				JavaSystem.@out.println("signature verified.");
			}
			else
			{
				JavaSystem.@out.println("signature verification failed.");
			}
		}

		private static byte[] getLineSeparator()
		{
			string nl = Strings.lineSeparator();
			byte[] nlBytes = new byte[nl.Length];

			for (int i = 0; i != nlBytes.Length; i++)
			{
				nlBytes[i] = (byte)nl[i];
			}

			return nlBytes;
		}

		/*
		 * create a clear text signed file.
		 */
		private static void signFile(string fileName, InputStream keyIn, OutputStream @out, char[] pass, string digestName)
		{
			int digest;

			if (digestName.Equals("SHA256"))
			{
				digest = PGPUtil.SHA256;
			}
			else if (digestName.Equals("SHA384"))
			{
				digest = PGPUtil.SHA384;
			}
			else if (digestName.Equals("SHA512"))
			{
				digest = PGPUtil.SHA512;
			}
			else if (digestName.Equals("MD5"))
			{
				digest = PGPUtil.MD5;
			}
			else if (digestName.Equals("RIPEMD160"))
			{
				digest = PGPUtil.RIPEMD160;
			}
			else
			{
				digest = PGPUtil.SHA1;
			}

			PGPSecretKey pgpSecKey = PGPExampleUtil.readSecretKey(keyIn);
			PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(pass));
			PGPSignatureGenerator sGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), digest)).setProvider("BC"));
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

			sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);

			Iterator it = pgpSecKey.getPublicKey().getUserIDs();
			if (it.hasNext())
			{
				spGen.setSignerUserID(false, (string)it.next());
				sGen.setHashedSubpackets(spGen.generate());
			}

			InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));
			ArmoredOutputStream aOut = new ArmoredOutputStream(@out);

			aOut.beginClearText(digest);

			//
			// note the last \n/\r/\r\n in the file is ignored
			//
			ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
			int lookAhead = readInputLine(lineOut, fIn);

			processLine(aOut, sGen, lineOut.toByteArray());

			if (lookAhead != -1)
			{
				do
				{
					lookAhead = readInputLine(lineOut, lookAhead, fIn);

					sGen.update((byte)'\r');
					sGen.update((byte)'\n');

					processLine(aOut, sGen, lineOut.toByteArray());
				} while (lookAhead != -1);
			}

			fIn.close();

			aOut.endClearText();

			BCPGOutputStream bOut = new BCPGOutputStream(aOut);

			sGen.generate().encode(bOut);

			aOut.close();
		}

		private static void processLine(PGPSignature sig, byte[] line)
		{
			int length = getLengthWithoutWhiteSpace(line);
			if (length > 0)
			{
				sig.update(line, 0, length);
			}
		}

		private static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
		{
			// note: trailing white space needs to be removed from the end of
			// each line for signature calculation RFC 4880 Section 7.1
			int length = getLengthWithoutWhiteSpace(line);
			if (length > 0)
			{
				sGen.update(line, 0, length);
			}

			aOut.write(line, 0, line.Length);
		}

		private static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
		{
			int end = line.Length - 1;

			while (end >= 0 && isWhiteSpace(line[end]))
			{
				end--;
			}

			return end + 1;
		}

		private static bool isLineEnding(byte b)
		{
			return b == (byte)'\r' || b == (byte)'\n';
		}

		private static int getLengthWithoutWhiteSpace(byte[] line)
		{
			int end = line.Length - 1;

			while (end >= 0 && isWhiteSpace(line[end]))
			{
				end--;
			}

			return end + 1;
		}

		private static bool isWhiteSpace(byte b)
		{
			return isLineEnding(b) || b == (byte)'\t' || b == (byte)' ';
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			if (args[0].Equals("-s"))
			{
				InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(args[2]));
				FileOutputStream @out = new FileOutputStream(args[1] + ".asc");

				if (args.Length == 4)
				{
					signFile(args[1], keyIn, @out, args[3].ToCharArray(), "SHA1");
				}
				else
				{
					signFile(args[1], keyIn, @out, args[3].ToCharArray(), args[4]);
				}
			}
			else if (args[0].Equals("-v"))
			{
				if (args[1].IndexOf(".asc", StringComparison.Ordinal) < 0)
				{
					JavaSystem.err.println(@"file needs to end in "".asc""");
					System.exit(1);
				}
				FileInputStream @in = new FileInputStream(args[1]);
				InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(args[2]));

				verifyFile(@in, keyIn, args[1].Substring(0, args[1].Length - 4));
			}
			else
			{
				JavaSystem.err.println("usage: ClearSignedFileProcessor [-s file keyfile passPhrase]|[-v sigFile keyFile]");
			}
		}
	}

}