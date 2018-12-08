using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using PBEKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.PBEKeyEncryptionMethodGenerator;
	using PGPDataEncryptor = org.bouncycastle.openpgp.@operator.PGPDataEncryptor;
	using PGPDataEncryptorBuilder = org.bouncycastle.openpgp.@operator.PGPDataEncryptorBuilder;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;
	using PGPKeyEncryptionMethodGenerator = org.bouncycastle.openpgp.@operator.PGPKeyEncryptionMethodGenerator;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	/// <summary>
	/// Generator for encrypted objects.
	/// <para>
	/// A PGPEncryptedDataGenerator is used by configuring one or more {@link #methods encryption
	/// methods}, and then invoking one of the open functions to create an OutputStream that raw data can
	/// be supplied to for encryption:</para>
	/// <ul>
	/// <li>If the length of the data to be written is known in advance, use
	/// <seealso cref="#open(OutputStream, long)"/> to create a packet containing a single encrypted object.</li>
	/// <li>If the length of the data is unknown, use <seealso cref="#open(OutputStream, byte[])"/> to create an
	/// packet consisting of a series of encrypted objects (partials).</li>
	/// </ul>
	/// <para>
	/// Raw data is not typically written directly to the OutputStream obtained from a
	/// PGPEncryptedDataGenerator. The OutputStream is usually wrapped by a
	/// <seealso cref="PGPLiteralDataGenerator"/>, and often with a <seealso cref="PGPCompressedDataGenerator"/> between.
	/// </para>
	/// </para><para>
	/// Once plaintext data for encryption has been written to the constructed OutputStream, writing of
	/// the encrypted object stream is completed by closing the OutputStream obtained from the
	/// <code>open()</code> method, or equivalently invoking <seealso cref="#close()"/> on this generator.
	/// </p>
	/// </summary>
	public class PGPEncryptedDataGenerator : SymmetricKeyAlgorithmTags, StreamGenerator
	{
		// TODO: These seem to belong on the PBE classes. Are they even used now?
		/// <summary>
		/// Specifier for SHA-1 S2K PBE generator.
		/// </summary>
		public const int S2K_SHA1 = HashAlgorithmTags_Fields.SHA1;

		/// <summary>
		/// Specifier for SHA-224 S2K PBE generator.
		/// </summary>
		public const int S2K_SHA224 = HashAlgorithmTags_Fields.SHA224;

		/// <summary>
		/// Specifier for SHA-256 S2K PBE generator.
		/// </summary>
		public const int S2K_SHA256 = HashAlgorithmTags_Fields.SHA256;

		/// <summary>
		/// Specifier for SHA-384 S2K PBE generator.
		/// </summary>
		public const int S2K_SHA384 = HashAlgorithmTags_Fields.SHA384;

		/// <summary>
		/// Specifier for SHA-512 S2K PBE generator.
		/// </summary>
		public const int S2K_SHA512 = HashAlgorithmTags_Fields.SHA512;

		private BCPGOutputStream pOut;
		private OutputStream cOut;
		private bool oldFormat = false;
		private PGPDigestCalculator digestCalc;
		private OutputStream genOut;
		private PGPDataEncryptorBuilder dataEncryptorBuilder;

		private List methods = new ArrayList();
		private int defAlgorithm;
		private SecureRandom rand;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="encryptorBuilder"> builder to create actual data encryptor. </param>
		public PGPEncryptedDataGenerator(PGPDataEncryptorBuilder encryptorBuilder) : this(encryptorBuilder, false)
		{
		}

		/// <summary>
		/// Base constructor with the option to turn on formatting for PGP 2.6.x compatibility.
		/// </summary>
		/// <param name="encryptorBuilder"> builder to create actual data encryptor. </param>
		/// <param name="oldFormat">        PGP 2.6.x compatibility required. </param>
		public PGPEncryptedDataGenerator(PGPDataEncryptorBuilder encryptorBuilder, bool oldFormat)
		{
			this.dataEncryptorBuilder = encryptorBuilder;
			this.oldFormat = oldFormat;

			this.defAlgorithm = dataEncryptorBuilder.getAlgorithm();
			this.rand = dataEncryptorBuilder.getSecureRandom();
		}

		/// <summary>
		/// Add a key encryption method to be used to encrypt the session data associated with this
		/// encrypted data.
		/// </summary>
		/// <param name="method"> key encryption method to use. </param>
		public virtual void addMethod(PGPKeyEncryptionMethodGenerator method)
		{
			methods.add(method);
		}

		private void addCheckSum(byte[] sessionInfo)
		{
			int check = 0;

			for (int i = 1; i != sessionInfo.Length - 2; i++)
			{
				check += sessionInfo[i] & 0xff;
			}

			sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
			sessionInfo[sessionInfo.Length - 1] = (byte)(check);
		}

		private byte[] createSessionInfo(int algorithm, byte[] keyBytes)
		{
			byte[] sessionInfo = new byte[keyBytes.Length + 3];
			sessionInfo[0] = (byte) algorithm;
			JavaSystem.arraycopy(keyBytes, 0, sessionInfo, 1, keyBytes.Length);
			addCheckSum(sessionInfo);
			return sessionInfo;
		}

		/// <summary>
		/// Create an OutputStream based on the configured methods.
		/// 
		/// If the supplied buffer is non <code>null</code> the stream returned will write a sequence of
		/// partial packets, otherwise the length will be used to output a fixed length packet.
		/// <para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> the stream to write encrypted packets to. </param>
		/// <param name="length"> the length of the data to be encrypted. Ignored if buffer is non
		///            <code>null</code>. </param>
		/// <param name="buffer"> a buffer to use to buffer and write partial packets. </param>
		/// <returns> the generator's output stream. </returns>
		/// <exception cref="IOException"> if an error occurs writing stream header information to the provider
		///             output stream. </exception>
		/// <exception cref="PGPException"> if an error occurs initialising PGP encryption for the configured
		///             encryption methods. </exception>
		/// <exception cref="IllegalStateException"> if this generator already has an open OutputStream, or no
		///             <seealso cref="#addMethod(PGPKeyEncryptionMethodGenerator) encryption methods"/> are
		///             configured. </exception>
		private OutputStream open(OutputStream @out, long length, byte[] buffer)
		{
			if (cOut != null)
			{
				throw new IllegalStateException("generator already in open state");
			}

			if (methods.size() == 0)
			{
				throw new IllegalStateException("no encryption methods specified");
			}

			byte[] key = null;

			pOut = new BCPGOutputStream(@out);

			defAlgorithm = dataEncryptorBuilder.getAlgorithm();
			rand = dataEncryptorBuilder.getSecureRandom();

			if (methods.size() == 1)
			{

				if (methods.get(0) is PBEKeyEncryptionMethodGenerator)
				{
					PBEKeyEncryptionMethodGenerator m = (PBEKeyEncryptionMethodGenerator)methods.get(0);

					key = m.getKey(dataEncryptorBuilder.getAlgorithm());

					pOut.writePacket(((PGPKeyEncryptionMethodGenerator)methods.get(0)).generate(defAlgorithm, null));
				}
				else
				{
					key = PGPUtil.makeRandomKey(defAlgorithm, rand);
					byte[] sessionInfo = createSessionInfo(defAlgorithm, key);
					PGPKeyEncryptionMethodGenerator m = (PGPKeyEncryptionMethodGenerator)methods.get(0);

					pOut.writePacket(m.generate(defAlgorithm, sessionInfo));
				}
			}
			else // multiple methods
			{
				key = PGPUtil.makeRandomKey(defAlgorithm, rand);
				byte[] sessionInfo = createSessionInfo(defAlgorithm, key);

				for (int i = 0; i != methods.size(); i++)
				{
					PGPKeyEncryptionMethodGenerator m = (PGPKeyEncryptionMethodGenerator)methods.get(i);

					pOut.writePacket(m.generate(defAlgorithm, sessionInfo));
				}
			}

			try
			{
				PGPDataEncryptor dataEncryptor = dataEncryptorBuilder.build(key);

				digestCalc = dataEncryptor.getIntegrityCalculator();

				if (buffer == null)
				{
					//
					// we have to add block size + 2 for the generated IV and + 1 + 22 if integrity protected
					//
					if (digestCalc != null)
					{
						pOut = new ClosableBCPGOutputStream(this, @out, PacketTags_Fields.SYM_ENC_INTEGRITY_PRO, length + dataEncryptor.getBlockSize() + 2 + 1 + 22);

						pOut.write(1); // version number
					}
					else
					{
						pOut = new ClosableBCPGOutputStream(this, @out, PacketTags_Fields.SYMMETRIC_KEY_ENC, length + dataEncryptor.getBlockSize() + 2, oldFormat);
					}
				}
				else
				{
					if (digestCalc != null)
					{
						pOut = new ClosableBCPGOutputStream(this, @out, PacketTags_Fields.SYM_ENC_INTEGRITY_PRO, buffer);
						pOut.write(1); // version number
					}
					else
					{
						pOut = new ClosableBCPGOutputStream(this, @out, PacketTags_Fields.SYMMETRIC_KEY_ENC, buffer);
					}
				}

				genOut = cOut = dataEncryptor.getOutputStream(pOut);

				if (digestCalc != null)
				{
					genOut = new TeeOutputStream(digestCalc.getOutputStream(), cOut);
				}

				byte[] inLineIv = new byte[dataEncryptor.getBlockSize() + 2];
				rand.nextBytes(inLineIv);
				inLineIv[inLineIv.Length - 1] = inLineIv[inLineIv.Length - 3];
				inLineIv[inLineIv.Length - 2] = inLineIv[inLineIv.Length - 4];

				genOut.write(inLineIv);

				return new WrappedGeneratorStream(genOut, this);
			}
			catch (Exception e)
			{
				throw new PGPException("Exception creating cipher", e);
			}
		}

		/// <summary>
		/// Create an OutputStream based on the configured methods to write a single encrypted object of
		/// known length.
		/// 
		/// <para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> the stream to write encrypted packets to. </param>
		/// <param name="length"> the length of the data to be encrypted. </param>
		/// <returns> the output stream to write data to for encryption. </returns>
		/// <exception cref="IOException"> if an error occurs writing stream header information to the provider
		///             output stream. </exception>
		/// <exception cref="PGPException"> if an error occurs initialising PGP encryption for the configured
		///             encryption methods. </exception>
		/// <exception cref="IllegalStateException"> if this generator already has an open OutputStream, or no
		///             <seealso cref="#addMethod(PGPKeyEncryptionMethodGenerator) encryption methods"/> are
		///             configured. </exception>
		public virtual OutputStream open(OutputStream @out, long length)
		{
			return this.open(@out, length, null);
		}

		/// <summary>
		/// Create an OutputStream which will encrypt the data as it is written to it. The stream of
		/// encrypted data will be written out in chunks (partial packets) according to the size of the
		/// passed in buffer.
		/// <para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// </para>
		/// <para>
		/// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2 bytes
		/// worth of the buffer will be used.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> the stream to write encrypted packets to. </param>
		/// <param name="buffer"> a buffer to use to buffer and write partial packets. The returned stream takes
		///            ownership of the buffer and will use it to buffer plaintext data for encryption. </param>
		/// <returns> the output stream to write data to for encryption. </returns>
		/// <exception cref="IOException"> if an error occurs writing stream header information to the provider
		///             output stream. </exception>
		/// <exception cref="PGPException"> if an error occurs initialising PGP encryption for the configured
		///             encryption methods. </exception>
		/// <exception cref="IllegalStateException"> if this generator already has an open OutputStream, or no
		///             <seealso cref="#addMethod(PGPKeyEncryptionMethodGenerator) encryption methods"/> are
		///             configured. </exception>
		public virtual OutputStream open(OutputStream @out, byte[] buffer)
		{
			return this.open(@out, 0, buffer);
		}

		/// <summary>
		/// Close off the encrypted object - this is equivalent to calling close on the stream returned
		/// by the <code>open()</code> methods.
		/// <para>
		/// <b>Note</b>: This does not close the underlying output stream, only the stream on top of it
		/// created by the <code>open()</code> method.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IOException"> if an error occurs writing trailing information (such as integrity check
		///             information) to the underlying stream. </exception>
		public virtual void close()
		{
			if (cOut != null)
			{
				if (digestCalc != null)
				{
					//
					// hand code a mod detection packet
					//
					BCPGOutputStream bOut = new BCPGOutputStream(genOut, PacketTags_Fields.MOD_DETECTION_CODE, 20);

					bOut.flush();

					byte[] dig = digestCalc.getDigest();

					cOut.write(dig);
				}

				cOut.close();

				cOut = null;
				pOut = null;
			}
		}

		public class ClosableBCPGOutputStream : BCPGOutputStream
		{
			private readonly PGPEncryptedDataGenerator outerInstance;

			public ClosableBCPGOutputStream(PGPEncryptedDataGenerator outerInstance, OutputStream @out, int symmetricKeyEnc, byte[] buffer) : base(@out, symmetricKeyEnc, buffer)
			{
				this.outerInstance = outerInstance;
			}

			public ClosableBCPGOutputStream(PGPEncryptedDataGenerator outerInstance, OutputStream @out, int symmetricKeyEnc, long length, bool oldFormat) : base(@out, symmetricKeyEnc, length, oldFormat)
			{
				this.outerInstance = outerInstance;
			}

			public ClosableBCPGOutputStream(PGPEncryptedDataGenerator outerInstance, OutputStream @out, int symEncIntegrityPro, long length) : base(@out, symEncIntegrityPro, length)
			{
				this.outerInstance = outerInstance;
			}

			public override void close()
			{
				 this.finish();
			}
		}
	}

}