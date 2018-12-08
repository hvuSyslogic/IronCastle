using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ArmoredInputStream = org.bouncycastle.bcpg.ArmoredInputStream;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using DecoderException = org.bouncycastle.util.encoders.DecoderException;

	/// <summary>
	/// PGP utilities.
	/// </summary>
	public class PGPUtil : HashAlgorithmTags
	{
		private static string defProvider = "BC";

		/// <summary>
		/// Return an appropriate name for the hash algorithm represented by the passed
		/// in hash algorithm ID number.
		/// </summary>
		/// <param name="hashAlgorithm"> the algorithm ID for a hash algorithm. </param>
		/// <returns> a String representation of the hash name. </returns>
		public static string getDigestName(int hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case HashAlgorithmTags_Fields.SHA1:
				return "SHA1";
			case HashAlgorithmTags_Fields.MD2:
				return "MD2";
			case HashAlgorithmTags_Fields.MD5:
				return "MD5";
			case HashAlgorithmTags_Fields.RIPEMD160:
				return "RIPEMD160";
			case HashAlgorithmTags_Fields.SHA256:
				return "SHA256";
			case HashAlgorithmTags_Fields.SHA384:
				return "SHA384";
			case HashAlgorithmTags_Fields.SHA512:
				return "SHA512";
			case HashAlgorithmTags_Fields.SHA224:
				return "SHA224";
			case HashAlgorithmTags_Fields.TIGER_192:
				return "TIGER";
			default:
				throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
			}
		}

		/// <summary>
		/// Return an appropriate name for the signature algorithm represented by the passed
		/// in public key and hash algorithm ID numbers.
		/// </summary>
		/// <param name="keyAlgorithm">  the algorithm ID for the public key algorithm used in the signature. </param>
		/// <param name="hashAlgorithm"> the algorithm ID for the hash algorithm used. </param>
		/// <returns> a String representation of the signature name. </returns>
		public static string getSignatureName(int keyAlgorithm, int hashAlgorithm)
		{
			string encAlg;

			switch (keyAlgorithm)
			{
			case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
			case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
				encAlg = "RSA";
				break;
			case PublicKeyAlgorithmTags_Fields.DSA:
				encAlg = "DSA";
				break;
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT: // in some malformed cases.
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
				encAlg = "ElGamal";
				break;
			default:
				throw new PGPException("unknown algorithm tag in signature:" + keyAlgorithm);
			}

			return getDigestName(hashAlgorithm) + "with" + encAlg;
		}

		/// <summary>
		/// Return an appropriate name for the symmetric algorithm represented by the passed
		/// in symmetric algorithm ID number.
		/// </summary>
		/// <param name="algorithm"> the algorithm ID for a symmetric cipher. </param>
		/// <returns> a String representation of the cipher name. </returns>
		public static string getSymmetricCipherName(int algorithm)
		{
			switch (algorithm)
			{
			case SymmetricKeyAlgorithmTags_Fields.NULL:
				return null;
			case SymmetricKeyAlgorithmTags_Fields.TRIPLE_DES:
				return "DESEDE";
			case SymmetricKeyAlgorithmTags_Fields.IDEA:
				return "IDEA";
			case SymmetricKeyAlgorithmTags_Fields.CAST5:
				return "CAST5";
			case SymmetricKeyAlgorithmTags_Fields.BLOWFISH:
				return "Blowfish";
			case SymmetricKeyAlgorithmTags_Fields.SAFER:
				return "SAFER";
			case SymmetricKeyAlgorithmTags_Fields.DES:
				return "DES";
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
				return "AES";
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
				return "AES";
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				return "AES";
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_128:
				return "Camellia";
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_192:
				return "Camellia";
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_256:
				return "Camellia";
			case SymmetricKeyAlgorithmTags_Fields.TWOFISH:
				return "Twofish";
			default:
				throw new IllegalArgumentException("unknown symmetric algorithm: " + algorithm);
			}
		}

		/// <summary>
		/// Return the JCA/JCE provider that will be used by factory classes in situations where a
		/// provider must be determined on the fly.
		/// </summary>
		/// <returns> the name of the default provider. </returns>
		/// @deprecated unused 
		public static string getDefaultProvider()
		{
			// TODO: no longer used.
			return defProvider;
		}

		/// <summary>
		/// Set the provider to be used by the package when it is necessary to find one on the fly.
		/// </summary>
		/// <param name="provider"> the name of the JCA/JCE provider to use by default. </param>
		/// @deprecated unused 
		public static void setDefaultProvider(string provider)
		{
			defProvider = provider;
		}

		internal static MPInteger[] dsaSigToMpi(byte[] encoding)
		{
			ASN1InputStream aIn = new ASN1InputStream(encoding);

			ASN1Integer i1;
			ASN1Integer i2;

			try
			{
				ASN1Sequence s = (ASN1Sequence)aIn.readObject();

				i1 = (ASN1Integer)s.getObjectAt(0);
				i2 = (ASN1Integer)s.getObjectAt(1);
			}
			catch (IOException e)
			{
				throw new PGPException("exception encoding signature", e);
			}

			MPInteger[] values = new MPInteger[2];

			values[0] = new MPInteger(i1.getValue());
			values[1] = new MPInteger(i2.getValue());

			return values;
		}

		/// <summary>
		/// Generates a random key for a <seealso cref="SymmetricKeyAlgorithmTags symmetric encryption algorithm"/>
		/// .
		/// </summary>
		/// <param name="algorithm"> the symmetric key algorithm identifier. </param>
		/// <param name="random">    a source of random data. </param>
		/// <returns> a key of the length required by the specified encryption algorithm. </returns>
		/// <exception cref="PGPException"> if the encryption algorithm is unknown. </exception>
		public static byte[] makeRandomKey(int algorithm, SecureRandom random)
		{
			int keySize = 0;

			switch (algorithm)
			{
			case SymmetricKeyAlgorithmTags_Fields.TRIPLE_DES:
				keySize = 192;
				break;
			case SymmetricKeyAlgorithmTags_Fields.IDEA:
				keySize = 128;
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAST5:
				keySize = 128;
				break;
			case SymmetricKeyAlgorithmTags_Fields.BLOWFISH:
				keySize = 128;
				break;
			case SymmetricKeyAlgorithmTags_Fields.SAFER:
				keySize = 128;
				break;
			case SymmetricKeyAlgorithmTags_Fields.DES:
				keySize = 64;
				break;
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
				keySize = 128;
				break;
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
				keySize = 192;
				break;
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				keySize = 256;
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_128:
				keySize = 128;
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_192:
				keySize = 192;
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_256:
				keySize = 256;
				break;
			case SymmetricKeyAlgorithmTags_Fields.TWOFISH:
				keySize = 256;
				break;
			default:
				throw new PGPException("unknown symmetric algorithm: " + algorithm);
			}

			byte[] keyBytes = new byte[(keySize + 7) / 8];

			random.nextBytes(keyBytes);

			return keyBytes;
		}

		/// <summary>
		/// Write out the contents of the provided file as a literal data packet.
		/// </summary>
		/// <param name="out">      the stream to write the literal data to. </param>
		/// <param name="fileType"> the <seealso cref="PGPLiteralData"/> type to use for the file data. </param>
		/// <param name="file">     the file to write the contents of. </param>
		/// <exception cref="IOException"> if an error occurs reading the file or writing to the output stream. </exception>
		public static void writeFileToLiteralData(OutputStream @out, char fileType, File file)
		{
			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			OutputStream pOut = lData.open(@out, fileType, file);
			pipeFileContents(file, pOut, 32768);
		}

		/// <summary>
		/// Write out the contents of the provided file as a literal data packet in partial packet
		/// format.
		/// </summary>
		/// <param name="out">      the stream to write the literal data to. </param>
		/// <param name="fileType"> the <seealso cref="PGPLiteralData"/> type to use for the file data. </param>
		/// <param name="file">     the file to write the contents of. </param>
		/// <param name="buffer">   buffer to be used to chunk the file into partial packets. </param>
		/// <exception cref="IOException"> if an error occurs reading the file or writing to the output stream. </exception>
		/// <seealso cref= PGPLiteralDataGenerator#open(OutputStream, char, String, Date, byte[]) </seealso>
		public static void writeFileToLiteralData(OutputStream @out, char fileType, File file, byte[] buffer)
		{
			PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
			OutputStream pOut = lData.open(@out, fileType, file.getName(), new DateTime(file.lastModified()), buffer);
			pipeFileContents(file, pOut, buffer.Length);
		}

		private static void pipeFileContents(File file, OutputStream pOut, int bufferSize)
		{
			byte[] buf = new byte[bufferSize];

			FileInputStream @in = new FileInputStream(file);
			try
			{
				int len;
				while ((len = @in.read(buf)) > 0)
				{
					pOut.write(buf, 0, len);
				}

				pOut.close();
			}
			finally
			{
				Arrays.fill(buf, (byte)0);
				try
				{
					@in.close();
				}
				catch (IOException)
				{
					// ignore...
				}
			}
		}

		private const int READ_AHEAD = 60;

		private static bool isPossiblyBase64(int ch)
		{
			return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/') || (ch == '\r') || (ch == '\n');
		}

		/// <summary>
		/// Obtains a stream that can be used to read PGP data from the provided stream.
		/// <para>
		/// If the initial bytes of the underlying stream are binary PGP encodings, then the stream will
		/// be returned directly, otherwise an <seealso cref="ArmoredInputStream"/> is used to wrap the provided
		/// stream and remove ASCII-Armored encoding.
		/// </para>
		/// </summary>
		/// <param name="in"> the stream to be checked and possibly wrapped. </param>
		/// <returns> a stream that will return PGP binary encoded data. </returns>
		/// <exception cref="IOException"> if an error occurs reading the stream, or initialising the
		/// <seealso cref="ArmoredInputStream"/>. </exception>
		public static InputStream getDecoderStream(InputStream @in)
		{
			if (!@in.markSupported())
			{
				@in = new BufferedInputStreamExt(@in);
			}

			@in.mark(READ_AHEAD);

			int ch = @in.read();


			if ((ch & 0x80) != 0)
			{
				@in.reset();

				return @in;
			}
			else
			{
				if (!isPossiblyBase64(ch))
				{
					@in.reset();

					return new ArmoredInputStream(@in);
				}

				byte[] buf = new byte[READ_AHEAD];
				int count = 1;
				int index = 1;

				buf[0] = (byte)ch;
				while (count != READ_AHEAD && (ch = @in.read()) >= 0)
				{
					if (!isPossiblyBase64(ch))
					{
						@in.reset();

						return new ArmoredInputStream(@in);
					}

					if (ch != '\n' && ch != '\r')
					{
						buf[index++] = (byte)ch;
					}

					count++;
				}

				@in.reset();

				//
				// nothing but new lines, little else, assume regular armoring
				//
				if (count < 4)
				{
					return new ArmoredInputStream(@in);
				}

				//
				// test our non-blank data
				//
				byte[] firstBlock = new byte[8];

				JavaSystem.arraycopy(buf, 0, firstBlock, 0, firstBlock.Length);

				try
				{
					byte[] decoded = Base64.decode(firstBlock);

					//
					// it's a base64 PGP block.
					//
					if ((decoded[0] & 0x80) != 0)
					{
						return new ArmoredInputStream(@in, false);
					}

					return new ArmoredInputStream(@in);
				}
				catch (DecoderException e)
				{
					throw new IOException(e.Message);
				}
			}
		}

		public class BufferedInputStreamExt : BufferedInputStream
		{
			public BufferedInputStreamExt(InputStream input) : base(input)
			{
			}

			public virtual int available()
			{
				lock (this)
				{
					int result = base.available();
					if (result < 0)
					{
						result = int.MaxValue;
					}
					return result;
				}
			}
		}
	}

}