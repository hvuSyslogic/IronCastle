namespace org.bouncycastle.openpgp
{

	using InputStreamPacket = org.bouncycastle.bcpg.InputStreamPacket;
	using SymmetricEncIntegrityPacket = org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using PGPDataDecryptor = org.bouncycastle.openpgp.@operator.PGPDataDecryptor;
	using PGPDataDecryptorFactory = org.bouncycastle.openpgp.@operator.PGPDataDecryptorFactory;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A PGP encrypted data object.
	/// <para>
	/// Encrypted data packets are decrypted using a <seealso cref="PGPDataDecryptor"/> obtained from a
	/// <seealso cref="PGPDataDecryptorFactory"/>.
	/// </para>
	/// </summary>
	public abstract class PGPEncryptedData : SymmetricKeyAlgorithmTags
	{
		public class TruncatedStream : InputStream
		{
			private readonly PGPEncryptedData outerInstance;

			internal int[] lookAhead = new int[22];
			internal int bufPtr;
			internal InputStream @in;

			public TruncatedStream(PGPEncryptedData outerInstance, InputStream @in)
			{
				this.outerInstance = outerInstance;
				for (int i = 0; i != lookAhead.Length; i++)
				{
					if ((lookAhead[i] = @in.read()) < 0)
					{
						throw new EOFException();
					}
				}

				bufPtr = 0;
				this.@in = @in;
			}

			public virtual int read()
			{
				int ch = @in.read();

				if (ch >= 0)
				{
					int c = lookAhead[bufPtr];

					lookAhead[bufPtr] = ch;
					bufPtr = (bufPtr + 1) % lookAhead.Length;

					return c;
				}

				return -1;
			}

			public virtual int[] getLookAhead()
			{
				int[] tmp = new int[lookAhead.Length];
				int count = 0;

				for (int i = bufPtr; i != lookAhead.Length; i++)
				{
					tmp[count++] = lookAhead[i];
				}
				for (int i = 0; i != bufPtr; i++)
				{
					tmp[count++] = lookAhead[i];
				}

				return tmp;
			}
		}

		internal InputStreamPacket encData;
		internal InputStream encStream;
		internal TruncatedStream truncStream;
		internal PGPDigestCalculator integrityCalculator;

		public PGPEncryptedData(InputStreamPacket encData)
		{
			this.encData = encData;
		}

		/// <summary>
		/// Return the raw input stream for the data stream.
		/// <para>
		/// Note this stream is shared with all other encryption methods in the same
		/// <seealso cref="PGPEncryptedDataList"/> and with any decryption methods in sub-classes, so consuming
		/// this stream will affect decryption.
		/// </para> </summary>
		/// <returns> the encrypted data in this packet. </returns>
		public virtual InputStream getInputStream()
		{
			return encData.getInputStream();
		}

		/// <summary>
		/// Checks whether the packet is integrity protected.
		/// </summary>
		/// <returns> <code>true</code> if there is a modification detection code package associated with
		///         this stream </returns>
		public virtual bool isIntegrityProtected()
		{
			return (encData is SymmetricEncIntegrityPacket);
		}

		/// <summary>
		/// Verifies the integrity of the packet against the modification detection code associated with
		/// it in the stream.
		/// <para>
		/// Note: This can only be called after the message has been read.
		/// </para> </summary>
		/// <returns> <code>true</code> if the message verifies, <code>false</code> otherwise. </returns>
		/// <exception cref="PGPException"> if the message is not {@link #isIntegrityProtected() integrity
		///             protected}. </exception>
		public virtual bool verify()
		{
			if (!this.isIntegrityProtected())
			{
				throw new PGPException("data not integrity protected.");
			}

			//
			// make sure we are at the end.
			//
			while (encStream.read() >= 0)
			{
				// do nothing
			}

			//
			// process the MDC packet
			//
			int[] lookAhead = truncStream.getLookAhead();

			OutputStream dOut = integrityCalculator.getOutputStream();

			dOut.write((byte)lookAhead[0]);
			dOut.write((byte)lookAhead[1]);

			byte[] digest = integrityCalculator.getDigest();
			byte[] streamDigest = new byte[digest.Length];

			for (int i = 0; i != streamDigest.Length; i++)
			{
				streamDigest[i] = (byte)lookAhead[i + 2];
			}

			return Arrays.constantTimeAreEqual(digest, streamDigest);
		}
	}

}