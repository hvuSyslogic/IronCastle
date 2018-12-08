using org.bouncycastle.asn1;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	public class PKCS7TypedStream : CMSTypedStream
	{
		private readonly ASN1Encodable content;

		public PKCS7TypedStream(ASN1ObjectIdentifier oid, ASN1Encodable encodable) : base(oid)
		{

			content = encodable;
		}

		public virtual ASN1Encodable getContent()
		{
			return content;
		}

		public override InputStream getContentStream()
		{
			try
			{
				return getContentStream(content);
			}
			catch (IOException e)
			{
				throw new CMSRuntimeException("unable to convert content to stream: " + e.Message, e);
			}
		}

		public override void drain()
		{
			getContentStream(content); // this will parse in the data
		}

		private InputStream getContentStream(ASN1Encodable encodable)
		{
			byte[] encoded = encodable.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
			int index = 1;

			while ((encoded[index] & 0xff) > 127)
			{
				index++;
			}

			index++;

			return new ByteArrayInputStream(encoded, index, encoded.Length - index);
		}
	}

}