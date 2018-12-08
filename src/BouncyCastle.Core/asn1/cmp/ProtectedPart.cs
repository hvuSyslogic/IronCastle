namespace org.bouncycastle.asn1.cmp
{

	public class ProtectedPart : ASN1Object
	{
		private PKIHeader header;
		private PKIBody body;

		private ProtectedPart(ASN1Sequence seq)
		{
			header = PKIHeader.getInstance(seq.getObjectAt(0));
			body = PKIBody.getInstance(seq.getObjectAt(1));
		}

		public static ProtectedPart getInstance(object o)
		{
			if (o is ProtectedPart)
			{
				return (ProtectedPart)o;
			}

			if (o != null)
			{
				return new ProtectedPart(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public ProtectedPart(PKIHeader header, PKIBody body)
		{
			this.header = header;
			this.body = body;
		}

		public virtual PKIHeader getHeader()
		{
			return header;
		}

		public virtual PKIBody getBody()
		{
			return body;
		}

		/// <summary>
		/// <pre>
		/// ProtectedPart ::= SEQUENCE {
		///                    header    PKIHeader,
		///                    body      PKIBody
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(header);
			v.add(body);

			return new DERSequence(v);
		}
	}

}