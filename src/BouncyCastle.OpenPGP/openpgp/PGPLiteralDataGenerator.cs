using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using BCPGOutputStream = org.bouncycastle.bcpg.BCPGOutputStream;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Generator for producing literal data packets.
	/// <para>
	/// A PGPLiteralData is used by invoking one of the open functions to create an OutputStream that raw
	/// data can be supplied to for encoding:  </para>
	/// <ul>
	/// <li>If the length of the data to be written is known in advance, use
	/// <seealso cref="#open(OutputStream, char, String, long, Date)"/> to create a packet containing a single
	/// literal data object.</li>
	/// <li>If the length of the data is unknown, use
	/// <seealso cref="#open(OutputStream, char, String, Date, byte[])"/> to create a packet consisting of a series
	/// of literal data objects (partials).</li>
	/// </ul>
	/// <para>
	/// A PGPLiteralDataGenerator is usually used to wrap the OutputStream
	/// <seealso cref="PGPEncryptedDataGenerator#open(OutputStream, byte[]) obtained"/> from a
	/// <seealso cref="PGPEncryptedDataGenerator"/> or a <seealso cref="PGPCompressedDataGenerator"/>.
	/// </para>
	/// </para><para>
	/// Once literal data has been written to the constructed OutputStream, writing of the object stream
	/// is completed by closing the OutputStream obtained from the <code>open()</code> method, or
	/// equivalently invoking <seealso cref="#close()"/> on this generator.
	/// </p>
	/// </summary>
	public class PGPLiteralDataGenerator : StreamGenerator
	{
		/// <summary>
		/// Format tag for binary literal data </summary>
		public const char BINARY = PGPLiteralData.BINARY;
		/// <summary>
		/// Format tag for textual literal data </summary>
		public const char TEXT = PGPLiteralData.TEXT;
		/// <summary>
		/// Format tag for UTF-8 encoded textual literal data </summary>
		public const char UTF8 = PGPLiteralData.UTF8;

		/// <summary>
		/// The special name indicating a "for your eyes only" packet.
		/// </summary>
		// TODO: Not used?
		public const string CONSOLE = PGPLiteralData.CONSOLE;

		/// <summary>
		/// The special time for a modification time of "now" or
		/// the present time.
		/// </summary>
		public static readonly DateTime NOW = PGPLiteralData.NOW;

		private BCPGOutputStream pkOut;
		private bool oldFormat = false;

		/// <summary>
		/// Constructs a generator for literal data objects.
		/// </summary>
		public PGPLiteralDataGenerator()
		{
		}

		/// <summary>
		/// Constructs a generator for literal data objects, specifying to use new or old (PGP 2.6.x
		/// compatible) format.
		/// <para>
		/// This can be used for compatibility with PGP 2.6.x.
		/// </para> </summary>
		/// <param name="oldFormat"> <code>true</code> to use PGP 2.6.x compatible format. </param>
		public PGPLiteralDataGenerator(bool oldFormat)
		{
			this.oldFormat = oldFormat;
		}

		private void writeHeader(OutputStream @out, char format, byte[] encName, long modificationTime)
		{
			@out.write(format);

			@out.write((byte)encName.Length);

			for (int i = 0; i != encName.Length; i++)
			{
				@out.write(encName[i]);
			}

			long modDate = modificationTime / 1000;

			@out.write((byte)(modDate >> 24));
			@out.write((byte)(modDate >> 16));
			@out.write((byte)(modDate >> 8));
			@out.write((byte)(modDate));
		}

		/// <summary>
		/// Open a literal data packet, returning a stream to store the data inside the packet.
		/// <para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> the underlying output stream to write the literal data packet to. </param>
		/// <param name="format"> the format of the literal data that will be written to the output stream (one
		///            of <seealso cref="#BINARY"/>, <seealso cref="#TEXT"/> or <seealso cref="#UTF8"/>). </param>
		/// <param name="name"> the name of the "file" to encode in the literal data object. </param>
		/// <param name="length"> the length of the data that will be written. </param>
		/// <param name="modificationTime"> the time of last modification we want stored. </param>
		public virtual OutputStream open(OutputStream @out, char format, string name, long length, DateTime modificationTime)
		{
			if (pkOut != null)
			{
				throw new IllegalStateException("generator already in open state");
			}

			byte[] encName = Strings.toUTF8ByteArray(name);

			pkOut = new BCPGOutputStream(@out, PacketTags_Fields.LITERAL_DATA, length + 2 + encName.Length + 4, oldFormat);

			writeHeader(pkOut, format, encName, modificationTime.Ticks);

			return new WrappedGeneratorStream(pkOut, this);
		}

		/// <summary>
		/// Open a literal data packet, returning a stream to store the data inside the packet as an
		/// indefinite-length stream. The stream is written out as a series of partial packets with a
		/// chunk size determined by the size of the passed in buffer.
		/// <para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// 
		/// </para>
		/// <para>
		/// <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2 bytes
		/// worth of the buffer will be used.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> the underlying output stream to write the literal data packet to. </param>
		/// <param name="format"> the format of the literal data that will be written to the output stream (one
		///            of <seealso cref="#BINARY"/>, <seealso cref="#TEXT"/> or <seealso cref="#UTF8"/>). </param>
		/// <param name="name"> the name of the "file" to encode in the literal data object. </param>
		/// <param name="modificationTime"> the time of last modification we want stored (will be stored to
		///            second level precision). </param>
		/// <param name="buffer"> a buffer to use to buffer and write partial packets. The returned stream takes
		///            ownership of the buffer.
		/// </param>
		/// <returns> the output stream to write data to. </returns>
		/// <exception cref="IOException"> if an error occurs writing stream header information to the provider
		///             output stream. </exception>
		/// <exception cref="IllegalStateException"> if this generator already has an open OutputStream. </exception>
		public virtual OutputStream open(OutputStream @out, char format, string name, DateTime modificationTime, byte[] buffer)
		{
			if (pkOut != null)
			{
				throw new IllegalStateException("generator already in open state");
			}

			pkOut = new BCPGOutputStream(@out, PacketTags_Fields.LITERAL_DATA, buffer);

			byte[] encName = Strings.toUTF8ByteArray(name);

			writeHeader(pkOut, format, encName, modificationTime.Ticks);

			return new WrappedGeneratorStream(pkOut, this);
		}

		/// <summary>
		/// Open a literal data packet for the passed in File object, returning an output stream for
		/// saving the file contents.
		/// <para>
		/// This method configures the generator to store the file contents in a single literal data
		/// packet, taking the filename and modification time from the file, but does not store the
		/// actual file data.
		/// </para>
		/// </para><para>
		/// The stream created can be closed off by either calling close() on the stream or close() on
		/// the generator. Closing the returned stream does not close off the OutputStream parameter out.
		/// </p> </summary>
		/// <param name="out"> the underlying output stream to write the literal data packet to. </param>
		/// <param name="format"> the format of the literal data that will be written to the output stream (one
		///            of <seealso cref="#BINARY"/>, <seealso cref="#TEXT"/> or <seealso cref="#UTF8"/>). </param>
		/// <param name="file"> the file to determine the length and filename from. </param>
		/// <returns> the output stream to write data to. </returns>
		/// <exception cref="IOException"> if an error occurs writing stream header information to the provider
		///             output stream. </exception>
		/// <exception cref="IllegalStateException"> if this generator already has an open OutputStream. </exception>
		public virtual OutputStream open(OutputStream @out, char format, File file)
		{
			return open(@out, format, file.getName(), file.length(), new DateTime(file.lastModified()));
		}

		/// <summary>
		/// Close the literal data packet - this is equivalent to calling close on the stream
		/// returned by the open() method.
		/// </summary>
		/// <exception cref="IOException"> </exception>
		public virtual void close()
		{
			if (pkOut != null)
			{
				pkOut.finish();
				pkOut.flush();
				pkOut = null;
			}
		}
	}

}