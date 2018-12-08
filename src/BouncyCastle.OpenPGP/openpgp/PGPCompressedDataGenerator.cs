using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using CBZip2OutputStream = org.bouncycastle.apache.bzip2.CBZip2OutputStream;
	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using CompressionAlgorithmTags = org.bouncycastle.bcpg.CompressionAlgorithmTags;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;

	/// <summary>
	/// Generator for producing compressed data packets.
	/// <para>
	/// A PGPCompressedDataGenerator is used by invoking one of the open functions to create an
	/// OutputStream that raw data can be supplied to for compression:
	/// </para><ul>
	/// <li>If the data needs to written out in blocks, use <seealso cref="#open(OutputStream, byte[])"/> to create a
	/// packet consisting of a series of compressed data objects (partials).</li>
	/// </ul>
	/// 
	/// <para>
	/// A PGPCompressedDataGenerator is usually used to wrap the OutputStream
	/// <seealso cref="PGPEncryptedDataGenerator#open(OutputStream, byte[]) obtained"/> from a
	/// <seealso cref="PGPEncryptedDataGenerator"/> (i.e. to compress data prior to encrypting it).
	/// </para>
	/// </para><para>
	/// Raw data is not typically written directly to the OutputStream obtained from a
	/// PGPCompressedDataGenerator. The OutputStream is usually wrapped by a
	/// <seealso cref="PGPLiteralDataGenerator"/>, which encodes the raw data prior to compression.
	/// </p>
	/// <para>
	/// Once data for compression has been written to the constructed OutputStream, writing of the object
	/// stream is completed by closing the OutputStream obtained from the <code>#open()</code> method, or
	/// equivalently invoking <seealso cref="#close()"/> on this generator.
	/// </para>
	/// </summary>
	public class PGPCompressedDataGenerator : CompressionAlgorithmTags, StreamGenerator
	{
		private int algorithm;
		private int compression;

		private OutputStream dOut;
		private BCPGOutputStream pkOut;

		/// <summary>
		/// Construct a new compressed data generator.
		/// </summary>
		/// <param name="algorithm"> the identifier of the <seealso cref="CompressionAlgorithmTags compression algorithm"/>
		///            to use. </param>
		public PGPCompressedDataGenerator(int algorithm) : this(algorithm, Deflater.DEFAULT_COMPRESSION)
		{
		}

		/// <summary>
		/// Construct a new compressed data generator.
		/// </summary>
		/// <param name="algorithm"> the identifier of the <seealso cref="CompressionAlgorithmTags compression algorithm"/>
		///            to use. </param>
		/// <param name="compression"> the <seealso cref="Deflater"/> compression level to use. </param>
		public PGPCompressedDataGenerator(int algorithm, int compression)
		{
			switch (algorithm)
			{
				case CompressionAlgorithmTags_Fields.UNCOMPRESSED:
				case CompressionAlgorithmTags_Fields.ZIP:
				case CompressionAlgorithmTags_Fields.ZLIB:
				case CompressionAlgorithmTags_Fields.BZIP2:
					break;
				default:
					throw new IllegalArgumentException("unknown compression algorithm");
			}

			if (compression != Deflater.DEFAULT_COMPRESSION)
			{
				if ((compression < Deflater.NO_COMPRESSION) || (compression > Deflater.BEST_COMPRESSION))
				{
					throw new IllegalArgumentException("unknown compression level: " + compression);
				}
			}

			this.algorithm = algorithm;
			this.compression = compression;
		}

		/// <summary>
		/// Return an OutputStream which will save the data being written to
		/// the compressed object.
		/// <para>
		/// The stream created can be closed off by either calling close()
		/// on the stream or close() on the generator. Closing the returned
		/// stream does not close off the OutputStream parameter out.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> underlying OutputStream to be used. </param>
		/// <returns> OutputStream </returns>
		/// <exception cref="IOException"> </exception>
		/// <exception cref="IllegalStateException"> </exception>
		public virtual OutputStream open(OutputStream @out)
		{
			if (dOut != null)
			{
				throw new IllegalStateException("generator already in open state");
			}

			this.pkOut = new BCPGOutputStream(@out, PacketTags_Fields.COMPRESSED_DATA);

			doOpen();

			return new WrappedGeneratorStream(dOut, this);
		}

		/// <summary>
		/// Return an OutputStream which will compress the data as it is written to it. The stream will
		/// be written out in chunks (partials) according to the size of the passed in buffer.
		/// <para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// </para>
		/// <para>
		/// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2 bytes
		/// worth of the buffer will be used.
		/// </para>
		/// <para>
		/// <b>Note</b>: using this may break compatibility with RFC 1991 compliant tools. Only recent
		/// OpenPGP implementations are capable of accepting these streams.
		/// </para>
		/// </summary>
		/// <param name="out"> the stream to write compressed packets to. </param>
		/// <param name="buffer"> a buffer to use to buffer and write partial packets. The returned stream takes
		///            ownership of the buffer and will use it to buffer plaintext data for compression. </param>
		/// <returns> the output stream to write data to. </returns>
		/// <exception cref="IOException"> if an error occurs writing stream header information to the provider
		///             output stream. </exception>
		/// <exception cref="PGPException"> </exception>
		/// <exception cref="IllegalStateException"> if this generator already has an open OutputStream. </exception>
		public virtual OutputStream open(OutputStream @out, byte[] buffer)
		{
			if (dOut != null)
			{
				throw new IllegalStateException("generator already in open state");
			}

			this.pkOut = new BCPGOutputStream(@out, PacketTags_Fields.COMPRESSED_DATA, buffer);

			doOpen();

			return new WrappedGeneratorStream(dOut, this);
		}

		private void doOpen()
		{
			pkOut.write(algorithm);

			switch (algorithm)
			{
				case CompressionAlgorithmTags_Fields.UNCOMPRESSED:
					dOut = pkOut;
					break;
				case CompressionAlgorithmTags_Fields.ZIP:
					dOut = new SafeDeflaterOutputStream(this, pkOut, compression, true);
					break;
				case CompressionAlgorithmTags_Fields.ZLIB:
					dOut = new SafeDeflaterOutputStream(this, pkOut, compression, false);
					break;
				case CompressionAlgorithmTags_Fields.BZIP2:
					dOut = new SafeCBZip2OutputStream(pkOut);
					break;
				default:
					// Constructor should guard against this possibility
					throw new IllegalStateException();
			}
		}

		/// <summary>
		/// Close the compressed object - this is equivalent to calling close on the stream
		/// returned by the open() method.
		/// </summary>
		/// <exception cref="IOException"> </exception>
		public virtual void close()
		{
			if (dOut != null)
			{
				if (dOut != pkOut)
				{
					dOut.close();
				}

				dOut = null;

				pkOut.finish();
				pkOut.flush();
				pkOut = null;
			}
		}

		public class SafeCBZip2OutputStream : CBZip2OutputStream
		{
			public SafeCBZip2OutputStream(OutputStream output) : base(output)
			{
			}

			public override void close()
			{
				finish();
			}
		}

		public class SafeDeflaterOutputStream : DeflaterOutputStream
		{
			private readonly PGPCompressedDataGenerator outerInstance;

			public SafeDeflaterOutputStream(PGPCompressedDataGenerator outerInstance, OutputStream output, int compression, bool nowrap) : base(output, new Deflater(compression, nowrap))
			{
				this.outerInstance = outerInstance;
			}

			public virtual void close()
			{
				finish();
				def.end();
			}
		}
	}

}