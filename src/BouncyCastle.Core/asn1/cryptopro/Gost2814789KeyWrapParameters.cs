using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.cryptopro
{
	
	public class Gost2814789KeyWrapParameters : ASN1Object
	{
		private readonly ASN1ObjectIdentifier encryptionParamSet;
		private readonly byte[] ukm;

		private Gost2814789KeyWrapParameters(ASN1Sequence seq)
		{
			if (seq.size() == 2)
			{
				this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
				this.ukm = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
			}
			else if (seq.size() == 1)
			{
				this.encryptionParamSet = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
				this.ukm = null;
			}
			else
			{
				throw new IllegalArgumentException("unknown sequence length: " + seq.size());
			}
		}

		public static Gost2814789KeyWrapParameters getInstance(object obj)
		{
			if (obj is Gost2814789KeyWrapParameters)
			{
				return (Gost2814789KeyWrapParameters)obj;
			}

			if (obj != null)
			{
				return new Gost2814789KeyWrapParameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public Gost2814789KeyWrapParameters(ASN1ObjectIdentifier encryptionParamSet) : this(encryptionParamSet, null)
		{
		}

		public Gost2814789KeyWrapParameters(ASN1ObjectIdentifier encryptionParamSet, byte[] ukm)
		{
			this.encryptionParamSet = encryptionParamSet;
			this.ukm = Arrays.clone(ukm);
		}

		public virtual ASN1ObjectIdentifier getEncryptionParamSet()
		{
			return encryptionParamSet;
		}

		public virtual byte[] getUkm()
		{
			return Arrays.clone(ukm);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(encryptionParamSet);
			if (ukm != null)
			{
				v.add(new DEROctetString(ukm));
			}

			return new DERSequence(v);
		}
	}

}