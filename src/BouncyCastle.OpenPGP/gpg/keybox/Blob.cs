using org.bouncycastle.gpg.keybox;

namespace org.bouncycastle.gpg.keybox
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;

	/// <summary>
	/// GnuPG keybox blob.
	/// Based on:
	/// </summary>
	/// <seealso cref= <a href="http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=kbx/keybox-blob.c;hb=HEAD"></a> </seealso>

	public class Blob
	{
		protected internal static readonly byte[] magicBytes = "KBXf".getBytes();

		protected internal readonly int @base; // position from start of keybox file.
		protected internal readonly long length;
		protected internal readonly BlobType type;
		protected internal readonly int version;

		public Blob(int @base, long length, BlobType type, int version)
		{
			this.@base = @base;
			this.length = length;
			this.type = type;
			this.version = version;
		}


		/// <summary>
		/// Return an instance of a blob from the source.
		/// Will return null if no more blobs exist.
		/// </summary>
		/// <param name="source"> The source, KeyBoxByteBuffer, ByteBuffer, byte[], InputStream or File.
		/// @return </param>
		/// <exception cref="Exception"> </exception>
		internal static Blob getInstance(object source, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier)
		{
			if (source == null)
			{
				throw new IllegalArgumentException("Cannot take get instance of null");
			}

			KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(source);

			if (!buffer.hasRemaining())
			{
				return null;
			}

			int @base = buffer.position();
			long len = buffer.u32();
			BlobType type = BlobType.fromByte(buffer.u8());
			int version = buffer.u8();

			switch (type.innerEnumValue)
			{

			case BlobType.InnerEnum.EMPTY_BLOB:
				break;
			case BlobType.InnerEnum.FIRST_BLOB:
				return FirstBlob.parseContent(@base, len, type, version, buffer);
			case BlobType.InnerEnum.X509_BLOB:
				return CertificateBlob.parseContent(@base, len, type, version, buffer, blobVerifier);
			case BlobType.InnerEnum.OPEN_PGP_BLOB:
				return PublicKeyRingBlob.parseContent(@base, len, type, version, buffer, keyFingerPrintCalculator, blobVerifier);
			}

			return null;

		}


		public virtual BlobType getType()
		{
			return type;
		}

		public virtual int getVersion()
		{
			return version;
		}


	}

}