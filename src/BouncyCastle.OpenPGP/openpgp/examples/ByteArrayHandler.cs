using org.bouncycastle.bcpg;
using org.bouncycastle.util.encoders;

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
	/// Simple routine to encrypt and decrypt using a passphrase.
	/// This service routine provides the basic PGP services between
	/// byte arrays.
	/// 
	/// Note: this code plays no attention to -CONSOLE in the file name
	/// the specification of "_CONSOLE" in the filename.
	/// It also expects that a single pass phrase will have been used.
	/// 
	/// </summary>
	public class ByteArrayHandler
	{
		/// <summary>
		/// decrypt the passed in message stream
		/// </summary>
		/// <param name="encrypted">  The message to be decrypted. </param>
		/// <param name="passPhrase"> Pass phrase (key)
		/// </param>
		/// <returns> Clear text as a byte array.  I18N considerations are
		///         not handled by this routine </returns>
		/// <exception cref="IOException"> </exception>
		/// <exception cref="PGPException"> </exception>
		/// <exception cref="NoSuchProviderException"> </exception>
		public static byte[] decrypt(byte[] encrypted, char[] passPhrase)
		{
			InputStream @in = new ByteArrayInputStream(encrypted);

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

			PGPCompressedData cData = (PGPCompressedData)pgpFact.nextObject();

			pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

			PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

			return Streams.readAll(ld.getInputStream());
		}

		/// <summary>
		/// Simple PGP encryptor between byte[].
		/// </summary>
		/// <param name="clearData">  The test to be encrypted </param>
		/// <param name="passPhrase"> The pass phrase (key).  This method assumes that the
		///                   key is a simple pass phrase, and does not yet support
		///                   RSA or more sophisiticated keying. </param>
		/// <param name="fileName">   File name. This is used in the Literal Data Packet (tag 11)
		///                   which is really inly important if the data is to be
		///                   related to a file to be recovered later.  Because this
		///                   routine does not know the source of the information, the
		///                   caller can set something here for file name use that
		///                   will be carried.  If this routine is being used to
		///                   encrypt SOAP MIME bodies, for example, use the file name from the
		///                   MIME type, if applicable. Or anything else appropriate.
		/// </param>
		/// <param name="armor">
		/// </param>
		/// <returns> encrypted data. </returns>
		/// <exception cref="IOException"> </exception>
		/// <exception cref="PGPException"> </exception>
		/// <exception cref="NoSuchProviderException"> </exception>
		public static byte[] encrypt(byte[] clearData, char[] passPhrase, string fileName, int algorithm, bool armor)
		{
			if (string.ReferenceEquals(fileName, null))
			{
				fileName = PGPLiteralData.CONSOLE;
			}

			byte[] compressedData = compress(clearData, fileName, CompressionAlgorithmTags_Fields.ZIP);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = bOut;
			if (armor)
			{
				@out = new ArmoredOutputStream(@out);
			}

			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator((new JcePGPDataEncryptorBuilder(algorithm)).setSecureRandom(new SecureRandom()).setProvider("BC"));
			encGen.addMethod((new JcePBEKeyEncryptionMethodGenerator(passPhrase)).setProvider("BC"));

			OutputStream encOut = encGen.open(@out, compressedData.Length);

			encOut.write(compressedData);
			encOut.close();

			if (armor)
			{
				@out.close();
			}

			return bOut.toByteArray();
		}

		private static byte[] compress(byte[] clearData, string fileName, int algorithm)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
			OutputStream cos = comData.open(bOut); // open it with the final destination

			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

			// we want to generate compressed data. This might be a user option later,
			// in which case we would pass in bOut.
			OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, fileName, clearData.Length, DateTime.Now // current time
										 );

			pOut.write(clearData);
			pOut.close();

			comData.close();

			return bOut.toByteArray();
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			string passPhrase = "Dick Beck";
			char[] passArray = passPhrase.ToCharArray();

			byte[] original = "Hello world".GetBytes();
			JavaSystem.@out.println("Starting PGP test");
			byte[] encrypted = encrypt(original, passArray, "iway", PGPEncryptedDataGenerator.CAST5, true);

			JavaSystem.@out.println("\nencrypted data = '" + StringHelper.NewString(encrypted) + "'");
			byte[] decrypted = decrypt(encrypted,passArray);

			JavaSystem.@out.println("\ndecrypted data = '" + StringHelper.NewString(decrypted) + "'");

			encrypted = encrypt(original, passArray, "iway", PGPEncryptedDataGenerator.AES_256, false);

			JavaSystem.@out.println("\nencrypted data = '" + StringHelper.NewString(Hex.encode(encrypted)) + "'");
			decrypted = decrypt(encrypted, passArray);

			JavaSystem.@out.println("\ndecrypted data = '" + StringHelper.NewString(decrypted) + "'");
		}
	}

}