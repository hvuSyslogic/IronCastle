using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.pkcs
{


	public class PBEParameter : ASN1Object
	{
		internal ASN1Integer iterations;
		internal ASN1OctetString salt;

		public PBEParameter(byte[] salt, int iterations)
		{
			if (salt.Length != 8)
			{
				throw new IllegalArgumentException("salt length must be 8");
			}
			this.salt = new DEROctetString(salt);
			this.iterations = new ASN1Integer(iterations);
		}

		private PBEParameter(ASN1Sequence seq)
		{
			salt = (ASN1OctetString)seq.getObjectAt(0);
			iterations = (ASN1Integer)seq.getObjectAt(1);
		}

		public static PBEParameter getInstance(object obj)
		{
			if (obj is PBEParameter)
			{
				return (PBEParameter)obj;
			}
			else if (obj != null)
			{
				return new PBEParameter(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual BigInteger getIterationCount()
		{
			return iterations.getValue();
		}

		public virtual byte[] getSalt()
		{
			return salt.getOctets();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(salt);
			v.add(iterations);

			return new DERSequence(v);
		}
	}

}