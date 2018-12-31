using org.bouncycastle.math.ec;

namespace org.bouncycastle.asn1.ua
{
	
	public class DSTU4145PublicKey : ASN1Object
	{

		private ASN1OctetString pubKey;

		public DSTU4145PublicKey(ECPoint pubKey)
		{
			// We always use big-endian in parameter encoding
			this.pubKey = new DEROctetString(DSTU4145PointEncoder.encodePoint(pubKey));
		}

		private DSTU4145PublicKey(ASN1OctetString ocStr)
		{
			pubKey = ocStr;
		}

		public static DSTU4145PublicKey getInstance(object obj)
		{
			if (obj is DSTU4145PublicKey)
			{
				return (DSTU4145PublicKey)obj;
			}

			if (obj != null)
			{
				return new DSTU4145PublicKey(ASN1OctetString.getInstance(obj));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return pubKey;
		}

	}

}