﻿using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.examples
{

	using ArmoredOutputStream = org.bouncycastle.bcpg.ArmoredOutputStream;
	using CompressionAlgorithmTags = org.bouncycastle.bcpg.CompressionAlgorithmTags;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPGPObjectFactory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcePBEDataDecryptorFactoryBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
	using JcePBEKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
	using JcePGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePGPDataEncryptorBuilder;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// A simple utility class that encrypts/decrypts password based
	/// encryption files.
	/// <para>
	/// To encrypt a file: PBEFileProcessor -e [-ai] fileName passPhrase.<br>
	/// If -a is specified the output file will be "ascii-armored".<br>
	/// If -i is specified the output file will be "integrity protected".
	/// </para>
	/// <para>
	/// To decrypt: PBEFileProcessor -d fileName passPhrase.
	/// </para>
	/// <para>
	/// Note: this example will silently overwrite files, nor does it pay any attention to
	/// the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
	/// will have been used.
	/// </para>
	/// </summary>
	public class PBEFileProcessor
	{
		private static void decryptFile(string inputFileName, char[] passPhrase)
		{
			InputStream @in = new BufferedInputStream(new FileInputStream(inputFileName));
			decryptFile(@in, passPhrase);
			@in.close();
		}

		/*
		 * decrypt the passed in message stream
		 */
		private static void decryptFile(InputStream @in, char[] passPhrase)
		{
			@in = PGPUtil.getDecoderStream(@in);

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

			PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)enc.get(0);

			InputStream clear = pbe.getDataStream((new JcePBEDataDecryptorFactoryBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build(passPhrase));

			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

			//
			// if we're trying to read a file generated by someone other than us
			// the data might not be compressed, so we check the return type from
			// the factory and behave accordingly.
			//
			o = pgpFact.nextObject();
			if (o is PGPCompressedData)
			{
				PGPCompressedData cData = (PGPCompressedData)o;

				pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

				o = pgpFact.nextObject();
			}

			PGPLiteralData ld = (PGPLiteralData)o;
			InputStream unc = ld.getInputStream();

			OutputStream fOut = new BufferedOutputStream(new FileOutputStream(ld.getFileName()));

			Streams.pipeAll(unc, fOut);

			fOut.close();

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

		private static void encryptFile(string outputFileName, string inputFileName, char[] passPhrase, bool armor, bool withIntegrityCheck)
		{
			OutputStream @out = new BufferedOutputStream(new FileOutputStream(outputFileName));
			encryptFile(@out, inputFileName, passPhrase, armor, withIntegrityCheck);
			@out.close();
		}

		private static void encryptFile(OutputStream @out, string fileName, char[] passPhrase, bool armor, bool withIntegrityCheck)
		{
			if (armor)
			{
				@out = new ArmoredOutputStream(@out);
			}

			try
			{
				byte[] compressedData = PGPExampleUtil.compressFile(fileName, CompressionAlgorithmTags_Fields.ZIP);

				PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
					.setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

				encGen.addMethod((new JcePBEKeyEncryptionMethodGenerator(passPhrase)).setProvider("BC"));

				OutputStream encOut = encGen.open(@out, compressedData.Length);

				encOut.write(compressedData);
				encOut.close();

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

			if (args[0].Equals("-e"))
			{
				if (args[1].Equals("-a") || args[1].Equals("-ai") || args[1].Equals("-ia"))
				{
					encryptFile(args[2] + ".asc", args[2], args[3].ToCharArray(), true, (args[1].IndexOf('i') > 0));
				}
				else if (args[1].Equals("-i"))
				{
					encryptFile(args[2] + ".bpg", args[2], args[3].ToCharArray(), false, true);
				}
				else
				{
					encryptFile(args[1] + ".bpg", args[1], args[2].ToCharArray(), false, false);
				}
			}
			else if (args[0].Equals("-d"))
			{
				decryptFile(args[1], args[2].ToCharArray());
			}
			else
			{
				JavaSystem.err.println("usage: PBEFileProcessor -e [-ai]|-d file passPhrase");
			}
		}
	}

}