using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using CBZip2InputStream = org.bouncycastle.apache.bzip2.CBZip2InputStream;
	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using CompressedDataPacket = org.bouncycastle.bcpg.CompressedDataPacket;
	using CompressionAlgorithmTags = org.bouncycastle.bcpg.CompressionAlgorithmTags;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;

	/// <summary>
	/// A PGP compressed data object.
	/// </summary>
	public class PGPCompressedData : CompressionAlgorithmTags
	{
		internal CompressedDataPacket data;

		/// <summary>
		/// Construct a compressed data object, reading a single <seealso cref="PacketTags#COMPRESSED_DATA"/>
		/// packet from the stream.
		/// </summary>
		/// <param name="pIn"> a PGP input stream, with a compressed data packet as the current packet. </param>
		/// <exception cref="IOException"> if an error occurs reading the packet from the stream. </exception>
		public PGPCompressedData(BCPGInputStream pIn)
		{
			data = (CompressedDataPacket)pIn.readPacket();
		}

		/// <summary>
		/// Return the <seealso cref="CompressionAlgorithmTags compression algorithm"/> used for this packet.
		/// </summary>
		/// <returns> the compression algorithm code </returns>
		public virtual int getAlgorithm()
		{
			return data.getAlgorithm();
		}

		/// <summary>
		/// Return the raw input stream contained in the object.
		/// <para>
		/// Note that this stream is shared with the decompression stream, so consuming the returned
		/// stream will affect decompression.
		/// </para> </summary>
		/// <returns> the raw data in the compressed data packet. </returns>
		public virtual InputStream getInputStream()
		{
			return data.getInputStream();
		}

		/// <summary>
		/// Return an input stream that decompresses and returns data in the compressed packet.
		/// </summary>
		/// <returns> a stream over the uncompressed data. </returns>
		/// <exception cref="PGPException"> if an error occurs constructing the decompression stream. </exception>
		public virtual InputStream getDataStream()
		{
		  if (this.getAlgorithm() == CompressionAlgorithmTags_Fields.UNCOMPRESSED)
		  {
			  return this.getInputStream();
		  }
		  if (this.getAlgorithm() == CompressionAlgorithmTags_Fields.ZIP)
		  {
			  return new InflaterInputStreamAnonymousInnerClass(this, this.getInputStream(), new Inflater(true));
		  }
		  if (this.getAlgorithm() == CompressionAlgorithmTags_Fields.ZLIB)
		  {
			  return new InflaterInputStreamAnonymousInnerClass2(this, this.getInputStream());
		  }
		  if (this.getAlgorithm() == CompressionAlgorithmTags_Fields.BZIP2)
		  {
			  try
			  {
				  return new CBZip2InputStream(this.getInputStream());
			  }
			  catch (IOException e)
			  {
				  throw new PGPException("I/O problem with stream: " + e, e);
			  }
		  }

		  throw new PGPException("can't recognise compression algorithm: " + this.getAlgorithm());
		}

		public class InflaterInputStreamAnonymousInnerClass : InflaterInputStream
		{
			private readonly PGPCompressedData outerInstance;

			public InflaterInputStreamAnonymousInnerClass(PGPCompressedData outerInstance, InputStream getInputStream, Inflater java) : base(getInputStream, Inflater)
			{
				this.outerInstance = outerInstance;
				eof = false;
			}

					  // If the "nowrap" inflater option is used the stream can
					  // apparently overread - we override fill() and provide
					  // an extra byte for the end of the input stream to get
					  // around this.
					  //
					  // Totally weird...
					  //
			public void fill()
			{
				if (eof)
				{
					throw new EOFException("Unexpected end of ZIP input stream");
				}

				len = this.@in.read(buf, 0, buf.length);

				if (len == -1)
				{
					buf[0] = 0;
					len = 1;
					eof = true;
				}

				inf.setInput(buf, 0, len);
			}

			private bool eof;
		}

		public class InflaterInputStreamAnonymousInnerClass2 : InflaterInputStream
		{
			private readonly PGPCompressedData outerInstance;

			public InflaterInputStreamAnonymousInnerClass2(PGPCompressedData outerInstance, InputStream getInputStream) : base(getInputStream)
			{
				this.outerInstance = outerInstance;
				eof = false;
			}

					  // If the "nowrap" inflater option is used the stream can
					  // apparently overread - we override fill() and provide
					  // an extra byte for the end of the input stream to get
					  // around this.
					  //
					  // Totally weird...
					  //
			public void fill()
			{
				if (eof)
				{
					throw new EOFException("Unexpected end of ZIP input stream");
				}

				len = this.@in.read(buf, 0, buf.length);

				if (len == -1)
				{
					buf[0] = 0;
					len = 1;
					eof = true;
				}

				inf.setInput(buf, 0, len);
			}

			private bool eof;
		}
	}

}