namespace org.bouncycastle.asn1.misc
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class IDEACBCPar : ASN1Object
	{
		internal ASN1OctetString iv;

		public static IDEACBCPar getInstance(object o)
		{
			if (o is IDEACBCPar)
			{
				return (IDEACBCPar)o;
			}
			else if (o != null)
			{
				return new IDEACBCPar(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public IDEACBCPar(byte[] iv)
		{
			this.iv = new DEROctetString(iv);
		}

		private IDEACBCPar(ASN1Sequence seq)
		{
			if (seq.size() == 1)
			{
				iv = (ASN1OctetString)seq.getObjectAt(0);
			}
			else
			{
				iv = null;
			}
		}

		public virtual byte[] getIV()
		{
			if (iv != null)
			{
				return Arrays.clone(iv.getOctets());
			}
			else
			{
				return null;
			}
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// IDEA-CBCPar ::= SEQUENCE {
		///                      iv    OCTET STRING OPTIONAL -- exactly 8 octets
		///                  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (iv != null)
			{
				v.add(iv);
			}

			return new DERSequence(v);
		}
	}

}