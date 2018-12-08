using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using BERSequenceGenerator = org.bouncycastle.asn1.BERSequenceGenerator;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using OutputCompressor = org.bouncycastle.@operator.OutputCompressor;

	/// <summary>
	/// General class for generating a compressed CMS message stream.
	/// <para>
	/// A simple example of usage.
	/// </para>
	/// <pre>
	///      CMSCompressedDataStreamGenerator gen = new CMSCompressedDataStreamGenerator();
	/// 
	///      OutputStream cOut = gen.open(outputStream, new ZlibCompressor());
	/// 
	///      cOut.write(data);
	/// 
	///      cOut.close();
	/// </pre>
	/// </summary>
	public class CMSCompressedDataStreamGenerator
	{
		public const string ZLIB = "1.2.840.113549.1.9.16.3.8";

		private int _bufferSize;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSCompressedDataStreamGenerator()
		{
		}

		/// <summary>
		/// Set the underlying string size for encapsulated data
		/// </summary>
		/// <param name="bufferSize"> length of octet strings to buffer the data. </param>
		public virtual void setBufferSize(int bufferSize)
		{
			_bufferSize = bufferSize;
		}

		/// <summary>
		/// Open a compressing output stream with the PKCS#7 content type OID of "data".
		/// </summary>
		/// <param name="out"> the stream to encode to. </param>
		/// <param name="compressor"> the type of compressor to use. </param>
		/// <returns> an output stream to write the data be compressed to. </returns>
		/// <exception cref="IOException"> </exception>
		public virtual OutputStream open(OutputStream @out, OutputCompressor compressor)
		{
			return open(CMSObjectIdentifiers_Fields.data, @out, compressor);
		}

		/// <summary>
		/// Open a compressing output stream.
		/// </summary>
		/// <param name="contentOID"> the content type OID. </param>
		/// <param name="out"> the stream to encode to. </param>
		/// <param name="compressor"> the type of compressor to use. </param>
		/// <returns> an output stream to write the data be compressed to. </returns>
		/// <exception cref="IOException"> </exception>
		public virtual OutputStream open(ASN1ObjectIdentifier contentOID, OutputStream @out, OutputCompressor compressor)
		{
			BERSequenceGenerator sGen = new BERSequenceGenerator(@out);

			sGen.addObject(CMSObjectIdentifiers_Fields.compressedData);

			//
			// Compressed Data
			//
			BERSequenceGenerator cGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

			cGen.addObject(new ASN1Integer(0));

			//
			// AlgorithmIdentifier
			//
			cGen.addObject(compressor.getAlgorithmIdentifier());

			//
			// Encapsulated ContentInfo
			//
			BERSequenceGenerator eiGen = new BERSequenceGenerator(cGen.getRawOutputStream());

			eiGen.addObject(contentOID);

			OutputStream octetStream = CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, true, _bufferSize);

			return new CmsCompressedOutputStream(this, compressor.getOutputStream(octetStream), sGen, cGen, eiGen);
		}

		public class CmsCompressedOutputStream : OutputStream
		{
			private readonly CMSCompressedDataStreamGenerator outerInstance;

			internal OutputStream _out;
			internal BERSequenceGenerator _sGen;
			internal BERSequenceGenerator _cGen;
			internal BERSequenceGenerator _eiGen;

			public CmsCompressedOutputStream(CMSCompressedDataStreamGenerator outerInstance, OutputStream @out, BERSequenceGenerator sGen, BERSequenceGenerator cGen, BERSequenceGenerator eiGen)
			{
				this.outerInstance = outerInstance;
				_out = @out;
				_sGen = sGen;
				_cGen = cGen;
				_eiGen = eiGen;
			}

			public virtual void write(int b)
			{
				_out.write(b);
			}


			public virtual void write(byte[] bytes, int off, int len)
			{
				_out.write(bytes, off, len);
			}

			public virtual void write(byte[] bytes)
			{
				_out.write(bytes);
			}

			public virtual void close()
			{
				_out.close();
				_eiGen.close();
				_cGen.close();
				_sGen.close();
			}
		}
	}

}