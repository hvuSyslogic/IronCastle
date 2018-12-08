using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.eac
{


	public class UnsignedInteger : ASN1Object
	{
		private int tagNo;
		private BigInteger value;

		public UnsignedInteger(int tagNo, BigInteger value)
		{
			this.tagNo = tagNo;
			this.value = value;
		}

		private UnsignedInteger(ASN1TaggedObject obj)
		{
			this.tagNo = obj.getTagNo();
			this.value = new BigInteger(1, ASN1OctetString.getInstance(obj, false).getOctets());
		}

		public static UnsignedInteger getInstance(object obj)
		{
			if (obj is UnsignedInteger)
			{
				return (UnsignedInteger)obj;
			}
			if (obj != null)
			{
				return new UnsignedInteger(ASN1TaggedObject.getInstance(obj));
			}

			return null;
		}

		private byte[] convertValue()
		{
			byte[] v = value.toByteArray();

			if (v[0] == 0)
			{
				byte[] tmp = new byte[v.Length - 1];

				JavaSystem.arraycopy(v, 1, tmp, 0, tmp.Length);

				return tmp;
			}

			return v;
		}

		public virtual int getTagNo()
		{
			return tagNo;
		}

		public virtual BigInteger getValue()
		{
			return value;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(false, tagNo, new DEROctetString(convertValue()));
		}
	}

}