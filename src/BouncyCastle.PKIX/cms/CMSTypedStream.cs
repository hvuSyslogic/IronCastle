namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Streams = org.bouncycastle.util.io.Streams;

	public class CMSTypedStream
	{
		private const int BUF_SIZ = 32 * 1024;

		private readonly ASN1ObjectIdentifier _oid;

		protected internal InputStream _in;

		public CMSTypedStream(InputStream @in) : this(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.data.getId(), @in, BUF_SIZ)
		{
		}

		public CMSTypedStream(string oid, InputStream @in) : this(new ASN1ObjectIdentifier(oid), @in, BUF_SIZ)
		{
		}

		public CMSTypedStream(string oid, InputStream @in, int bufSize) : this(new ASN1ObjectIdentifier(oid), @in, bufSize)
		{
		}

		public CMSTypedStream(ASN1ObjectIdentifier oid, InputStream @in) : this(oid, @in, BUF_SIZ)
		{
		}

		public CMSTypedStream(ASN1ObjectIdentifier oid, InputStream @in, int bufSize)
		{
			_oid = oid;
			_in = new FullReaderStream(new BufferedInputStream(@in, bufSize));
		}

		public CMSTypedStream(ASN1ObjectIdentifier oid)
		{
			_oid = oid;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return _oid;
		}

		public virtual InputStream getContentStream()
		{
			return _in;
		}

		public virtual void drain()
		{
			Streams.drain(_in);
			_in.close();
		}

		public class FullReaderStream : FilterInputStream
		{
			public FullReaderStream(InputStream @in) : base(@in)
			{
			}

			public virtual int read(byte[] buf, int off, int len)
			{
				int totalRead = Streams.readFully(base.@in, buf, off, len);
				return totalRead > 0 ? totalRead : -1;
			}
		}
	}

}