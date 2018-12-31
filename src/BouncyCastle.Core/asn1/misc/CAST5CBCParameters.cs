using org.bouncycastle.util;

namespace org.bouncycastle.asn1.misc
{
	
	public class CAST5CBCParameters : ASN1Object
	{
		internal ASN1Integer keyLength;
		internal ASN1OctetString iv;

		public static CAST5CBCParameters getInstance(object o)
		{
			if (o is CAST5CBCParameters)
			{
				return (CAST5CBCParameters)o;
			}
			else if (o != null)
			{
				return new CAST5CBCParameters(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CAST5CBCParameters(byte[] iv, int keyLength)
		{
			this.iv = new DEROctetString(Arrays.clone(iv));
			this.keyLength = new ASN1Integer(keyLength);
		}

		private CAST5CBCParameters(ASN1Sequence seq)
		{
			iv = (ASN1OctetString)seq.getObjectAt(0);
			keyLength = (ASN1Integer)seq.getObjectAt(1);
		}

		public virtual byte[] getIV()
		{
			return Arrays.clone(iv.getOctets());
		}

		public virtual int getKeyLength()
		{
			return keyLength.getValue().intValue();
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// cast5CBCParameters ::= SEQUENCE {
		///                           iv         OCTET STRING DEFAULT 0,
		///                                  -- Initialization vector
		///                           keyLength  INTEGER
		///                                  -- Key length, in bits
		///                      }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(iv);
			v.add(keyLength);

			return new DERSequence(v);
		}
	}

}