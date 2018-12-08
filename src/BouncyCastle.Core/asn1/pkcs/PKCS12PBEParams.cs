using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.pkcs
{


	public class PKCS12PBEParams : ASN1Object
	{
		internal ASN1Integer iterations;
		internal ASN1OctetString iv;

		public PKCS12PBEParams(byte[] salt, int iterations)
		{
			this.iv = new DEROctetString(salt);
			this.iterations = new ASN1Integer(iterations);
		}

		private PKCS12PBEParams(ASN1Sequence seq)
		{
			iv = (ASN1OctetString)seq.getObjectAt(0);
			iterations = ASN1Integer.getInstance(seq.getObjectAt(1));
		}

		public static PKCS12PBEParams getInstance(object obj)
		{
			if (obj is PKCS12PBEParams)
			{
				return (PKCS12PBEParams)obj;
			}
			else if (obj != null)
			{
				return new PKCS12PBEParams(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual BigInteger getIterations()
		{
			return iterations.getValue();
		}

		public virtual byte[] getIV()
		{
			return iv.getOctets();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(iv);
			v.add(iterations);

			return new DERSequence(v);
		}
	}

}