using org.bouncycastle.asn1;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;

	public class PKCS7ProcessableObject : CMSTypedData
	{
		private readonly ASN1ObjectIdentifier type;
		private readonly ASN1Encodable structure;

		public PKCS7ProcessableObject(ASN1ObjectIdentifier type, ASN1Encodable structure)
		{
			this.type = type;
			this.structure = structure;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return type;
		}

		public virtual void write(OutputStream cOut)
		{
			if (structure is ASN1Sequence)
			{
				ASN1Sequence s = ASN1Sequence.getInstance(structure);

				for (Iterator it = s.iterator(); it.hasNext();)
				{
					ASN1Encodable enc = (ASN1Encodable)it.next();

					cOut.write(enc.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
				}
			}
			else
			{
				byte[] encoded = structure.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
				int index = 1;

				while ((encoded[index] & 0xff) > 127)
				{
					index++;
				}

				index++;

				cOut.write(encoded, index, encoded.Length - index);
			}
		}

		public virtual object getContent()
		{
			return structure;
		}
	}

}